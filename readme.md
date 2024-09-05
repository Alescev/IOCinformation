# 🌍 IP Geolocation Explorer

IP Geolocation Explorer is a powerful and user-friendly tool that provides comprehensive information about IP addresses and domain names. It offers a rich set of features to help you investigate and analyze network entities.

## 🚀 Features

### 📊 Multi-Entity Lookup
- Look up information for up to 10 IP addresses or domain names simultaneously
- Support for both IPv4 and IPv6 addresses, domains and escaped values.

### 🗺️ Interactive Mapping
- Visualize locations on an interactive global map
- Color-coded markers for easy identification

### 🛡️ Reputation Analysis
- Aggregate safety scores from trusted sources:
  - VirusTotal
  - AbuseIPDB
  - GreyNoise
  - IPQualityScore

### 🔍 Detailed Information
- Comprehensive data for each entry:
  - Geographic location (country, city, region)
  - ISP and organization details
  - AS number
  - Timezone

### 🕵️ Threat Intelligence
- Integration with OpenCTI for advanced threat intelligence
- Direct link to OpenCTI dashboard for further investigation

### 🔄 Reverse DNS Lookup
- Perform reverse DNS lookups for IP addresses

### 📰 Related Articles
- Fetch relevant news articles using Bing Search API
- Customized search queries for more accurate results

### 📤 Export Capabilities
- Export results in multiple formats:
  - CSV for spreadsheet analysis
  - PDF for professional reporting
  - STIX for threat intelligence sharing

### 📁 Bulk Import
- Upload a CSV file with multiple IP addresses or domains

### ⚙️ Customizable Settings
- Configure API keys for various services
- Set OpenCTI URL for your specific instance

## 🛠️ Getting Started

1. Ensure Python is installed on your system.

2. Clone this repository:
   ```
   git clone https://github.com/Alescev/IOCinformation.git
   cd IOCinformation
   ```

3. Set up a virtual environment and install dependencies:
   ```
   python -m venv .venv
   source .venv/bin/activate  # On Windows, use: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

4. Create your configuration file:
   - Copy `config.example.py` to `config.py`
   - Open `config.py` and replace the placeholder API keys with your own

5. Launch the application:
   ```
   python main.py
   ```

## 🖥️ Usage

1. Enter IP addresses or domain names in the input field (comma-separated for multiple entries)
2. Click "Search" or press Enter to initiate the lookup
3. View results on the interactive map and in the detailed results panel
4. Use additional features like "More Info", "Detailed Reputation", and "Reverse DNS" for in-depth analysis
5. Export your results using the export buttons

## 🔑 API Keys

To fully utilize all features, you'll need to obtain API keys for the following services:

- VirusTotal
- AbuseIPDB
- GreyNoise
- IPQualityScore
- OpenCTI
- Bing Search

Enter these keys in the Settings panel within the application.
