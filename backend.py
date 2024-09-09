from PyQt5.QtCore import QObject, pyqtSlot, QUrl, QEventLoop
from PyQt5.QtWidgets import QApplication, QFileDialog
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtGui import QPixmap, QDesktopServices
import requests
import json
import folium
import io
import base64
import random
import re
import socket
import csv
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import tempfile
import os
from OTXv2 import OTXv2
from stix2 import IPv4Address, IPv6Address, Bundle, Indicator, Relationship, Location, Identity, DomainName
import urllib3
import concurrent.futures
from pycti import OpenCTIApiClient
import dns.resolver
import logging
import openai

# Import the config files
from config import API_KEYS, OPENCTI_URL

# Add this near the top of your file, after the imports
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Backend(QObject):
    def __init__(self):
        super().__init__()
        self.load_config()
        self.session = requests.Session()
        self.opencti_client = None
        self.init_opencti_client()
        self.openai_client = openai.OpenAI(api_key=self.api_keys['openai'])

    def load_config(self):
        try:
            from config import API_KEYS, OPENCTI_URL
            self.api_keys = API_KEYS
            self.opencti_url = OPENCTI_URL
        except ImportError:
            #updated with bing and openai keys.
            print("Error: config.py file is missing or corrupted. Using default values.")
            self.api_keys = {
                'vt': '', 'abuseipdb': '', 'greynoise': '', 'ipqualityscore': '', 'opencti': '', 'bing': '', 'openai': ''
            }
            self.opencti_url = ''

        self.masked_api_keys = {key: '*' * len(value) for key, value in self.api_keys.items()}
        self.masked_opencti_url = '*' * len(self.opencti_url)

    def init_opencti_client(self):
        try:
            self.opencti_client = OpenCTIApiClient(self.opencti_url, self.api_keys['opencti'])
            print("OpenCTI client initialized successfully")
        except Exception as e:
            print(f"Error initializing OpenCTI client: {str(e)}")
            self.opencti_client = None

    @pyqtSlot(str, result=str)
    def fetch_ip_info(self, input_data):
        entries = self.parse_input(input_data)[:10]
        results = []
        locations = []
        colors = []
        detailed_info = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_entry = {executor.submit(self.process_entry, entry): entry for entry in entries}
            for future in concurrent.futures.as_completed(future_to_entry):
                entry = future_to_entry[future]
                try:
                    result, location, color, info = future.result()
                    results.append(result)
                    if location:
                        locations.append(location)
                    colors.append(color)
                    detailed_info.append(info)
                except Exception as exc:
                    print(f'{entry} generated an exception: {exc}')
                    results.append(f"{entry}: Error - {str(exc)}")
                    colors.append('#808080')
                    detailed_info.append(None)

        # Fetch Bing search results for each entry
        for info in detailed_info:
            if info:
                query = info.get('original_domain') or info['query']
                is_domain = 'original_domain' in info
                bing_results = json.loads(self.fetch_bing_results(query, is_domain))
                if 'error' not in bing_results:
                    info['bing_results'] = bing_results['webPages']['value'][:5]  # Limit to top 5 results
                else:
                    info['bing_results'] = {"error": bing_results['error']}

        return json.dumps({
            "results": results,
            "map_data": self.generate_map(locations, colors),
            "colors": colors,
            "detailed_info": detailed_info
        })

    def parse_input(self, input_data):
        """Parse and clean input data (IP addresses or domains)."""
        cleaned = re.sub(r'[\[\](){}<>]', '', input_data)
        cleaned = cleaned.replace('[dot]', '.').replace('(dot)', '.').replace('[.]', '.')
        return [entry.strip() for entry in cleaned.split(',')]

    def is_valid_domain(self, domain):
        """Check if the given string is a valid domain name."""
        pattern = re.compile(
            r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
            r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
            r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
            r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
        )
        return bool(pattern.match(domain))

    def is_valid_ip(self, ip):
        """Check if the given string is a valid IP address."""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False

    def process_entry(self, entry):
        if self.is_valid_ip(entry):
            return self.process_ip(entry)
        elif self.is_valid_domain(entry):
            return self.process_domain(entry)
        else:
            raise ValueError(f"Invalid input: {entry}")

    def process_domain(self, domain):
        try:
            ip = self.resolve_domain(domain)
            result, location, color, info = self.process_ip(ip)
            info['original_domain'] = domain
            
            # Fetch OpenCTI data for the domain
            opencti_data = self.fetch_opencti_data(domain)
            info['opencti'] = opencti_data
            
            return f"{domain} ({ip}): {info['country']}, {info['city']}", location, color, info
        except Exception as e:
            raise Exception(f"Error processing domain {domain}: {str(e)}")

    def resolve_domain(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return answers[0].to_text()
        except dns.exception.DNSException as e:
            raise Exception(f"DNS resolution failed for {domain}: {str(e)}")

    def process_ip(self, ip):
        try:
            response = self.session.get(f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query')
            data = response.json()
            if data['status'] == 'success':
                result = f"{ip}: {data['country']}, {data['city']}"
                location = (data['lat'], data['lon'], ip)
                color = self.get_random_color()
                osint_data = self.fetch_osint_data(ip)
                opencti_data = self.fetch_opencti_data(ip)
                info = {**data, 'osint': osint_data, 'opencti': opencti_data}
                return result, location, color, info
            else:
                return f"{ip}: Unable to fetch information", None, '#808080', None
        except Exception as e:
            raise Exception(f"Error processing {ip}: {str(e)}")

    def fetch_osint_data(self, ip):
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            future_vt = executor.submit(self.fetch_virustotal_data, ip)
            future_abuseipdb = executor.submit(self.fetch_abuseipdb_data, ip)
            future_greynoise = executor.submit(self.fetch_greynoise_data, ip)
            future_ipqualityscore = executor.submit(self.fetch_ipqualityscore_data, ip)

            vt_data = future_vt.result()
            abuseipdb_data = future_abuseipdb.result()
            greynoise_data = future_greynoise.result()
            ipqualityscore_data = future_ipqualityscore.result()

        reputation = self.calculate_reputation(vt_data, abuseipdb_data, greynoise_data, ipqualityscore_data)
        
        return {
            "virustotal": vt_data,
            "abuseipdb": abuseipdb_data,
            "greynoise": greynoise_data,
            "ipqualityscore": ipqualityscore_data,
            "reputation": reputation
        }

    def fetch_virustotal_data(self, ip):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_keys['vt']
        }
        try:
            response = self.session.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                last_analysis_stats = data['data']['attributes']['last_analysis_stats']
                total = sum(last_analysis_stats.values())
                malicious = last_analysis_stats['malicious']
                return {
                    "score": f"{malicious}/{total}",
                    "percentage": round((malicious / total) * 100, 2) if total > 0 else 0
                }
        except Exception as e:
            print(f"Error fetching VirusTotal data: {str(e)}")
        return None

    def fetch_abuseipdb_data(self, ip):
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        headers = {
            "accept": "application/json",
            "key": self.api_keys['abuseipdb']
        }
        try:
            response = self.session.get(url, headers=headers, params=querystring)
            if response.status_code == 200:
                data = response.json()['data']
                return {
                    "abuse_confidence_score": data['abuseConfidenceScore'],
                    "total_reports": data['totalReports']
                }
        except Exception as e:
            print(f"Error fetching AbuseIPDB data: {str(e)}")
        return None

    def fetch_greynoise_data(self, ip):
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {
            "Accept": "application/json",
            "key": self.api_keys['greynoise']
        }
        try:
            response = self.session.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                return {
                    "classification": data.get("classification", "Unknown"),
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False)
                }
            elif response.status_code == 429:
                return {"classification": "API Limit Reached", "noise": False, "riot": False}
            else:
                return {"classification": "Unknown", "noise": False, "riot": False}
        except Exception as e:
            print(f"Error fetching GreyNoise data: {str(e)}")
            return {"classification": "Error", "noise": False, "riot": False}

    def fetch_ipqualityscore_data(self, ip):
        url = f"https://ipqualityscore.com/api/json/ip/{self.api_keys['ipqualityscore']}/{ip}"
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                data = response.json()
                return {
                    "fraud_score": data.get('fraud_score', 0),
                    "proxy": data.get('proxy', False),
                    "vpn": data.get('vpn', False),
                    "tor": data.get('tor', False)
                }
            else:
                print(f"IPQualityScore API error: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Error fetching IPQualityScore data: {str(e)}")
        return {"fraud_score": 0, "proxy": False, "vpn": False, "tor": False}

    def calculate_reputation(self, vt_data, abuseipdb_data, greynoise_data, ipqualityscore_data):
        score = 0
        sources = 0

        if vt_data:
            score += vt_data['percentage']
            sources += 1
        if abuseipdb_data:
            score += abuseipdb_data['abuse_confidence_score']
            sources += 1
        if greynoise_data:
            if greynoise_data['classification'] == 'malicious':
                score += 100
            elif greynoise_data['classification'] == 'benign':
                score += 0
            else:
                score += 50
            sources += 1
        if ipqualityscore_data:
            score += ipqualityscore_data['fraud_score']
            sources += 1

        if sources == 0:
            return {"status": "Unknown", "score": 0}
        
        average_score = score / sources
        if average_score < 33:
            return {"status": "Legit", "score": average_score}
        elif average_score < 66:
            return {"status": "Suspicious", "score": average_score}
        else:
            return {"status": "Malicious", "score": average_score}

    @staticmethod
    def get_random_color():
        """Generate a random color for map markers."""
        return f'#{random.randint(0, 0xFFFFFF):06x}'

    @staticmethod
    def parse_ip_addresses(ip_addresses):
        """Parse and clean IP addresses from input string."""
        cleaned = re.sub(r'[\[\](){}<>]', '', ip_addresses)
        cleaned = cleaned.replace('[dot]', '.').replace('(dot)', '.').replace('[.]', '.')
        return [ip.strip() for ip in cleaned.split(',')]

    def generate_map(self, locations, colors):
        m = folium.Map(location=[0, 0], zoom_start=2)

        for (lat, lon, ip), color in zip(locations, colors):
            folium.CircleMarker(
                location=[lat, lon],
                radius=8,
                popup=ip,
                color=color,
                fill=True,
                fillColor=color
            ).add_to(m)

        img_data = io.BytesIO()
        m.save(img_data, close_file=False)
        img_data.seek(0)
        return base64.b64encode(img_data.getvalue()).decode('utf-8')

    @pyqtSlot(str, result=str)
    def reverse_ip_lookup(self, ip):
        try:
            domains = socket.gethostbyaddr(ip)[0]
            if isinstance(domains, str):
                domains = [domains]
            return json.dumps({
                "status": "success",
                "domains": domains
            })
        except socket.herror:
            return json.dumps({
                "status": "error",
                "message": "No domain found for this IP"
            })
        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e)
            })

    @pyqtSlot(str, result=str)
    def export_csv(self, data):
        try:
            data = json.loads(data)
            filename, _ = QFileDialog.getSaveFileName(None, "Save CSV File", "", "CSV Files (*.csv)")
            if not filename:
                return json.dumps({"status": "cancelled", "message": "Export cancelled by user"})

            with open(filename, 'w', newline='') as csvfile:
                fieldnames = ['Input', 'IP', 'Country', 'City', 'ISP', 'VirusTotal Score', 'AbuseIPDB Score', 'GreyNoise Classification', 'IPQualityScore Fraud Score']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for info in data['detailed_info']:
                    if info:
                        writer.writerow({
                            'Input': info.get('original_domain', info['query']),
                            'IP': info['query'],
                            'Country': info['country'],
                            'City': info['city'],
                            'ISP': info['isp'],
                            'VirusTotal Score': info['osint']['virustotal']['score'] if info['osint']['virustotal'] else 'N/A',
                            'AbuseIPDB Score': info['osint']['abuseipdb']['abuse_confidence_score'] if info['osint']['abuseipdb'] else 'N/A',
                            'GreyNoise Classification': info['osint']['greynoise']['classification'] if info['osint']['greynoise'] else 'N/A',
                            'IPQualityScore Fraud Score': info['osint']['ipqualityscore']['fraud_score'] if info['osint']['ipqualityscore'] else 'N/A'
                        })

            return json.dumps({"status": "success", "filename": filename})
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})

    @pyqtSlot(str, result=str)
    def export_pdf(self, data):
        try:
            data = json.loads(data)
            filename, _ = QFileDialog.getSaveFileName(None, "Save PDF File", "", "PDF Files (*.pdf)")
            if not filename:
                return json.dumps({
                    "status": "cancelled",
                    "message": "Export cancelled by user"
                })

            doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
            elements = []
            styles = getSampleStyleSheet()

            # Custom style for the title
            title_style = ParagraphStyle(
                'Title',
                parent=styles['Title'],
                fontSize=24,
                spaceAfter=12,
                textColor=colors.darkblue
            )

            # Custom style for table headers
            header_style = ParagraphStyle(
                'Header',
                parent=styles['Normal'],
                fontSize=12,
                textColor=colors.white,
                alignment=1  # Center alignment
            )

            for info in data['detailed_info']:
                if info:
                    # Add Input (IP or domain) as title
                    input_value = info.get('original_domain', info['query'])
                    elements.append(Paragraph(f"Input: {input_value}", title_style))
                    elements.append(Spacer(1, 20))

                    # Create table data
                    table_data = [
                        [Paragraph('Field', header_style), Paragraph('Value', header_style)],
                        ['IP', info['query']],
                        ['Country', info['country']],
                        ['City', info['city']],
                        ['Region', info['regionName']],
                        ['ZIP', info['zip']],
                        ['Latitude', str(info['lat'])],
                        ['Longitude', str(info['lon'])],
                        ['Timezone', info['timezone']],
                        ['ISP', info['isp']],
                        ['Organization', info['org']],
                        ['AS', info['as']],
                        ['VirusTotal Score', info['osint']['virustotal']['score'] if info['osint']['virustotal'] else 'N/A'],
                        ['AbuseIPDB Score', str(info['osint']['abuseipdb']['abuse_confidence_score']) if info['osint']['abuseipdb'] else 'N/A'],
                        ['GreyNoise Classification', info['osint']['greynoise']['classification'] if info['osint']['greynoise'] else 'N/A'],
                        ['IPQualityScore Fraud Score', str(info['osint']['ipqualityscore']['fraud_score']) if info['osint']['ipqualityscore'] else 'N/A']
                    ]

                    # Create and style the table
                    table = Table(table_data, colWidths=[2*inch, 3.5*inch])
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 12),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                        ('FONTSIZE', (0, 1), (-1, -1), 10),
                        ('TOPPADDING', (0, 1), (-1, -1), 6),
                        ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ]))
                    elements.append(table)
                    elements.append(PageBreak())

            # Build the PDF
            doc.build(elements)

            return json.dumps({
                "status": "success",
                "filename": filename
            })
        except Exception as e:
            return json.dumps({
                "status": "error",
                "message": str(e)
            })

    @pyqtSlot(str, result=str)
    def export_stix(self, data):
        try:
            data = json.loads(data)
            stix_objects = []

            for info in data['detailed_info']:
                if info:
                    # Determine if it's an IP or domain
                    input_value = info.get('original_domain', info['query'])
                    ip_value = info['query']

                    if 'original_domain' in info:
                        domain_object = DomainName(value=info['original_domain'])
                        stix_objects.append(domain_object)

                    # Create IP object
                    if ':' in ip_value:
                        ip_object = IPv6Address(value=ip_value)
                    else:
                        ip_object = IPv4Address(value=ip_value)
                    
                    stix_objects.append(ip_object)

                    # Create Location object
                    location = Location(
                        country=info['country'],
                        region=info['regionName'],
                        city=info['city']
                    )
                    stix_objects.append(location)

                    # Create Identity object for the ISP
                    isp_identity = Identity(
                        name=info['isp'],
                        identity_class="organization"
                    )
                    stix_objects.append(isp_identity)

                    # Create Indicator object
                    indicator = Indicator(
                        name=f"Geolocation: {input_value}",
                        description=f"Geolocation data for {input_value}",
                        pattern=f"[{ip_object.type}:value = '{ip_value}']",
                        pattern_type="stix",
                        valid_from=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    )
                    stix_objects.append(indicator)

                    # Create Relationships
                    relationships = [
                        Relationship(relationship_type="indicates", source_ref=indicator.id, target_ref=ip_object.id),
                        Relationship(relationship_type="located-at", source_ref=ip_object.id, target_ref=location.id),
                        Relationship(relationship_type="uses", source_ref=isp_identity.id, target_ref=ip_object.id)
                    ]

                    if 'original_domain' in info:
                        relationships.append(Relationship(relationship_type="resolves-to", source_ref=domain_object.id, target_ref=ip_object.id))

                    stix_objects.extend(relationships)

            bundle = Bundle(objects=stix_objects)
            
            filename, _ = QFileDialog.getSaveFileName(None, "Save STIX File", "", "JSON Files (*.json)")
            if not filename:
                return json.dumps({"status": "cancelled", "message": "Export cancelled by user"})

            with open(filename, 'w') as f:
                f.write(bundle.serialize(pretty=True))

            return json.dumps({"status": "success", "filename": filename})
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})

    def fetch_opencti_data(self, entry):
        logger.debug(f"Fetching OpenCTI data for entry: {entry}")
        if not self.opencti_client:
            return {"found": False, "error": "OpenCTI client not available"}
        
        try:
            # Determine if the entry is an IP or domain
            is_ip = self.is_valid_ip(entry)
            
            # Prepare filters for the search
            if is_ip:
                entity_type = ["IPv4-Addr", "IPv6-Addr"]
            else:
                entity_type = ["Domain-Name"]
            
            filters = {
                "mode": "and",
                "filters": [
                    {"key": "value", "values": [entry]},
                    {"key": "entity_type", "values": entity_type}
                ],
                "filterGroups": []
            }
            
            logger.debug(f"OpenCTI query filters: {filters}")
            observables = self.opencti_client.stix_cyber_observable.list(filters=filters)
            logger.debug(f"OpenCTI query result: {observables}")
            
            if observables:
                # Entry found in OpenCTI
                observable = observables[0]
                return {
                    "found": True,
                    "id": observable.get("id", "N/A"),
                    "labels": [label.get("value", "N/A") for label in observable.get("objectLabel", [])],
                    "type": observable.get("entity_type", "N/A"),
                    "value": observable.get("value", "N/A")
                }
            else:
                # Entry not found in OpenCTI
                return {"found": False}
        except Exception as e:
            logger.exception(f"Error fetching OpenCTI data for {entry}")
            error_details = {
                "error_type": type(e).__name__,
                "error_message": str(e),
                "entry_queried": entry
            }
            print(f"Error fetching OpenCTI data: {error_details}")
            return {"found": False, "error": error_details}

    @pyqtSlot(str, result=str)
    def toggle_api_key_visibility(self, key):
        if key in self.api_keys:
            value = self.api_keys[key] if self.masked_api_keys[key].startswith('*') else '*' * len(self.api_keys[key])
            self.masked_api_keys[key] = value
            return json.dumps({"status": "success", "key": key, "value": value})
        elif key == 'opencti-url':
            value = self.opencti_url if self.masked_opencti_url.startswith('*') else '*' * len(self.opencti_url)
            self.masked_opencti_url = value
            return json.dumps({"status": "success", "key": key, "value": value})
        else:
            return json.dumps({"status": "error", "message": "Invalid API key"})

    @pyqtSlot(str, result=str)
    def update_api_settings(self, settings_json):
        try:
            settings = json.loads(settings_json)
            if 'apiKeys' not in settings or 'openctiUrl' not in settings:
                raise ValueError("Missing 'apiKeys' or 'openctiUrl' in settings")
            
            self.api_keys = settings['apiKeys']
            self.opencti_url = settings['openctiUrl']
            self.masked_api_keys = {key: '*' * len(value) for key, value in self.api_keys.items()}
            self.masked_opencti_url = '*' * len(self.opencti_url)
            
            # Update config.py file
            config_content = f"""
# API Keys
API_KEYS = {self.api_keys}

# OpenCTI URL
OPENCTI_URL = "{self.opencti_url}"
"""
            with open('config.py', 'w') as f:
                f.write(config_content)
            
            # Reinitialize OpenCTI client with new settings
            self.init_opencti_client()
            
            # Update OpenAI API key
            self.openai_client = openai.OpenAI(api_key=self.api_keys['openai'])
            
            return json.dumps({"status": "success"})
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})

    @pyqtSlot(str, result=str)
    def open_opencti_link(self, observable_id):
        try:
            url = f"{self.opencti_url}/dashboard/observations/observables/{observable_id}"
            QDesktopServices.openUrl(QUrl(url))
            return json.dumps({"status": "success"})
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})

    @pyqtSlot(str, result=str)
    def fetch_bing_results(self, query, is_domain=False):
        try:
            headers = {
                'Ocp-Apim-Subscription-Key': self.api_keys['bing'],
            }
            
            # Use the domain if available, otherwise use the IP
            search_query = query if is_domain else f'"{query}"'
            
            # Add escaped versions to the search query
            escaped_query = query.replace('.', '[.]').replace(':', '[:]')
            
            params = {
                'q': f'{search_query} OR "{escaped_query}" -site:{query}',
                'count': '50',
                'offset': '0',
                'mkt': 'en-US',
                'safesearch': 'Moderate'
            }
            response = requests.get('https://api.bing.microsoft.com/v7.0/search', headers=headers, params=params)
            response.raise_for_status()
            return json.dumps(response.json())
        except requests.exceptions.RequestException as e:
            if 'quota' in str(e).lower():
                return json.dumps({"error": "Bing API rate limit reached. Please try again later."})
            return json.dumps({"error": str(e)})

    @pyqtSlot(str, result=str)
    def generate_summary(self, data):
        try:
            data = json.loads(data)
            prompt = self.create_summary_prompt(data)
            
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cyber threat intelligence analyst. use the provided information to provide a useful and insightful summary of the data, using a technical and professional style. use a nice and clear formatting with bold for relevant words and subtitles. use markdown. Do not use bullets points, but rather sentences. if you find the tag hygiene it means that is market in the opencti platform as legitimate, so mentions that from the opencti platform it is considered legitimate without mentioning directly the hygiene tag. do not use bullet points."},
                    {"role": "user", "content": prompt}
                ]
            )
            
            summary = response.choices[0].message.content
            return json.dumps({"status": "success", "summary": summary})
        except Exception as e:
            return json.dumps({"status": "error", "message": str(e)})

    def create_summary_prompt(self, data):
        prompt = "Summarize the following IP geolocation and threat intelligence information with a technical and professional style. use sentences, not bullet points.:\n\n"
        for info in data['detailed_info']:
            if info:
                if 'original_domain' in info:
                    # This is a domain entry
                    prompt += f"Domain: {info['original_domain']}\n"
                    prompt += f"Associated IP: {info['query']}\n"
                    prompt += f"Location: {info['country']}, {info['city']}\n"
                    prompt += f"ISP: {info['isp']}\n"
                    prompt += f"Reputation: {info['osint']['reputation']['status']} (Score: {info['osint']['reputation']['score']})\n"
                else:
                    # This is an IP entry
                    prompt += f"IP: {info['query']}\n"
                    prompt += f"Location: {info['country']}, {info['city']}\n"
                    prompt += f"ISP: {info['isp']}\n"
                    prompt += f"Reputation: {info['osint']['reputation']['status']} (Score: {info['osint']['reputation']['score']})\n"
                
                if 'opencti' in info and info['opencti']['found']:
                    prompt += f"OpenCTI: Found (Labels: {', '.join(info['opencti']['labels'])})\n"
                prompt += "\n"
        return prompt