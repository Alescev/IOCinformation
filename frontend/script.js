// Wrap the entire script in a DOMContentLoaded event listener
document.addEventListener('DOMContentLoaded', function() {
    // Global variables
    let backend, currentData;

    // Initialize WebChannel connection
    new QWebChannel(qt.webChannelTransport, channel => {
        backend = channel.objects.backend;
    });

    // DOM element selectors
    const elements = {
        ipInput: document.getElementById('ip-input'),
        searchButton: document.getElementById('search-button'),
        ipCounter: document.getElementById('ip-counter'),
        resultsText: document.getElementById('results-text'),
        resultsContainer: document.getElementById('results-container'),
        mapContainer: document.getElementById('map-container'),
        mapElement: document.getElementById('map'),
        csvUpload: document.getElementById('csv-upload'),
        exportContainer: document.getElementById('export-container'),
    };

    // Add this function to toggle export buttons visibility
    function toggleExportButtons(show) {
        if (elements.exportContainer) {
            elements.exportContainer.style.display = show ? 'flex' : 'none';
        }
        const generateSummaryButton = document.getElementById('generate-summary');
        if (generateSummaryButton) {
            generateSummaryButton.style.display = show ? 'inline-block' : 'none';
        }
    }

    // Helper functions
    const updateIPCounter = count => {
        if (elements.ipCounter) {
            elements.ipCounter.textContent = `(${count} entries)`;
        }
    };

    const updateSearchButtonState = () => {
        if (elements.searchButton && elements.ipInput) {
            elements.searchButton.disabled = !elements.ipInput.value.trim();
        }
    };

    const getScoreClass = score => {
        if (score < 33) return 'low';
        if (score < 66) return 'medium';
        return 'high';
    };

    const getGreyNoiseScoreClass = data => {
        const classifications = {
            'malicious': 'high',
            'benign': 'low',
            'API Limit Reached': 'medium'
        };
        return classifications[data.classification] || 'medium';
    };

    // Event listeners
    if (elements.searchButton) {
        elements.searchButton.addEventListener('click', performSearch);
    }
    if (elements.ipInput) {
        elements.ipInput.addEventListener('keypress', event => {
            if (event.key === 'Enter') performSearch();
        });
        elements.ipInput.addEventListener('input', updateSearchButtonState);
    }

    ['csv', 'pdf', 'stix'].forEach(format => {
        const exportButton = document.getElementById(`export-${format}`);
        if (exportButton) {
            exportButton.addEventListener('click', () => exportData(format));
        }
    });

    const csvUploadButton = document.getElementById('csv-upload-button');
    if (csvUploadButton && elements.csvUpload) {
        csvUploadButton.addEventListener('click', () => elements.csvUpload.click());
        elements.csvUpload.addEventListener('change', handleCSVUpload);
    }

    // Add hover effects
    ['searchButton', 'ipInput', 'export-csv', 'export-pdf', 'export-stix'].forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener('mouseover', () => {
                element.style.transform = id === 'ipInput' ? 'translateY(-2px)' : 'scale(1.05)';
                element.style.transition = 'transform 0.2s ease';
            });
            element.addEventListener('mouseout', () => {
                element.style.transform = id === 'ipInput' ? 'translateY(0)' : 'scale(1)';
            });
        }
    });

    // Add event listeners for API key visibility toggle buttons
    ['vt', 'abuseipdb', 'greynoise', 'ipqualityscore', 'opencti'].forEach(key => {
        const toggleButton = document.getElementById(`${key}-api-key-toggle`);
        if (toggleButton) {
            toggleButton.addEventListener('click', () => toggleApiKeyVisibility(key));
        }
    });

    // Add this to the existing event listeners section
    document.getElementById('generate-summary').addEventListener('click', generateSummary);

    // Add this function to handle the summary generation
    function generateSummary() {
        if (!currentData || !currentData.detailed_info) {
            alert('No data to summarize. Please perform a search first.');
            return;
        }

        backend.generate_summary(JSON.stringify(currentData), function(response) {
            const data = JSON.parse(response);
            if (data.status === 'success') {
                const summaryContainer = document.getElementById('summary-container');
                const summaryContent = document.getElementById('summary-content');
                
                // Convert Markdown-style formatting to HTML
                let formattedSummary = data.summary
                    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')  // Bold text
                    .replace(/^# (.*$)/gm, '<h1>$1</h1>')  // H1 headers
                    .replace(/^## (.*$)/gm, '<h2>$1</h2>')  // H2 headers
                    .replace(/^### (.*$)/gm, '<h3>$1</h3>')  // H3 headers
                    .replace(/\n/g, '<br>');  // Line breaks

                summaryContent.innerHTML = formattedSummary;
                summaryContainer.style.display = 'block';
            } else {
                alert('Error generating summary: ' + data.message);
            }
        });
    }

    // Main functions
    function performSearch() {
        toggleExportButtons(false);
        const inputData = elements.ipInput.value;
        
        // Disable UI elements during search
        elements.searchButton.disabled = true;
        elements.searchButton.textContent = 'Searching...';
        [elements.resultsContainer, elements.mapContainer].forEach(el => el.style.opacity = '0.5');
        
        // Clear previous results
        elements.resultsText.innerHTML = '';

        backend.fetch_ip_info(inputData, response => {
            try {
                currentData = JSON.parse(response);
                updateIPCounter(currentData.results.length);
                
                currentData.results.forEach((result, index) => {
                    const legendItem = createLegendItem(result, index);
                    elements.resultsText.appendChild(legendItem);
                });
                
                updateMap(currentData.map_data);
                
                // Re-enable UI elements
                elements.searchButton.disabled = false;
                elements.searchButton.textContent = 'Search';
                [elements.resultsContainer, elements.mapContainer].forEach(el => el.style.opacity = '1');

                toggleExportButtons(true);
            } catch (error) {
                console.error('Error parsing response:', error);
                alert('An error occurred while processing the search results.');
                elements.searchButton.disabled = false;
                elements.searchButton.textContent = 'Search';
                [elements.resultsContainer, elements.mapContainer].forEach(el => el.style.opacity = '1');
            }
        });
    }

    function createLegendItem(result, index) {
        const legendItem = document.createElement('div');
        legendItem.className = 'legend-item';
        
        const mainContent = createMainContent(result, index);
        const reverseLookupInfo = document.createElement('div');
        reverseLookupInfo.className = 'reverse-lookup-info';
        reverseLookupInfo.style.display = 'none';
        
        legendItem.appendChild(mainContent);
        legendItem.appendChild(reverseLookupInfo);
        
        return legendItem;
    }

    function createMainContent(result, index) {
        const mainContent = document.createElement('div');
        mainContent.className = 'main-content';

        const ipInfo = document.createElement('div');
        ipInfo.className = 'ip-info';

        const colorBox = document.createElement('span');
        colorBox.className = 'color-box';
        colorBox.style.backgroundColor = currentData.colors[index];

        const textSpan = document.createElement('span');
        const info = currentData.detailed_info[index];
        const inputValue = info.original_domain || info.query;
        
        if (info.original_domain) {
            textSpan.innerHTML = `<span class="domain-name">${info.original_domain}</span> (${info.query}): ${info.country}, ${info.city}`;
        } else {
            textSpan.textContent = `${inputValue}: ${info.country}, ${info.city}`;
        }

        ipInfo.appendChild(colorBox);
        ipInfo.appendChild(textSpan);

        // Add reputation information
        const reputationInfo = createReputationInfo(index);
        ipInfo.appendChild(reputationInfo);

        mainContent.appendChild(ipInfo);

        // Add OpenCTI information
        const openctiInfo = createOpenCTIInfo(index);
        mainContent.appendChild(openctiInfo);

        const buttonContainer = document.createElement('div');
        buttonContainer.className = 'button-container';

        // Add "More Info" button
        const moreInfoButton = document.createElement('button');
        moreInfoButton.className = 'more-info-button';
        moreInfoButton.textContent = 'More Info';
        moreInfoButton.addEventListener('click', () => showMoreInfo(index));
        buttonContainer.appendChild(moreInfoButton);

        // Add "Detailed Reputation" button
        const detailedReputationButton = document.createElement('button');
        detailedReputationButton.className = 'detailed-reputation-button';
        detailedReputationButton.textContent = 'Detailed Reputation';
        detailedReputationButton.addEventListener('click', () => showDetailedReputation(index));
        buttonContainer.appendChild(detailedReputationButton);

        // Add "Reverse DNS" button only for IP addresses
        if (!info.original_domain) {
            const reverseLookupButton = document.createElement('button');
            reverseLookupButton.className = 'reverse-lookup-button';
            reverseLookupButton.textContent = 'Reverse DNS';
            reverseLookupButton.addEventListener('click', () => performReverseLookup(info.query));
            buttonContainer.appendChild(reverseLookupButton);
        }

        mainContent.appendChild(buttonContainer);

        const bingResultsContainer = document.createElement('div');
        bingResultsContainer.className = 'bing-results-container';
        
        const bingResultsHeader = document.createElement('h4');
        bingResultsHeader.textContent = 'Related Articles:';
        bingResultsContainer.appendChild(bingResultsHeader);

        if (info.bing_results && !info.bing_results.error) {
            const bingResultsList = document.createElement('ul');
            info.bing_results.forEach(result => {
                const listItem = document.createElement('li');
                const link = document.createElement('a');
                link.href = result.url;
                link.textContent = result.name;
                link.target = '_blank';
                listItem.appendChild(link);
                bingResultsList.appendChild(listItem);
            });
            bingResultsContainer.appendChild(bingResultsList);
        } else if (info.bing_results && info.bing_results.error) {
            const errorMessage = document.createElement('p');
            errorMessage.textContent = `Error: ${info.bing_results.error}`;
            errorMessage.style.color = 'red';
            bingResultsContainer.appendChild(errorMessage);
        }

        mainContent.appendChild(bingResultsContainer);

        return mainContent;
    }

    function createOpenCTIInfo(index) {
        const entryData = currentData.detailed_info[index];
        if (!entryData) {
            console.error('No data available for index:', index);
            return document.createElement('div'); // Return an empty div if no data
        }

        const openctiData = entryData.opencti;
        const isOriginalDomain = 'original_domain' in entryData;
        const openctiInfo = document.createElement('div');
        openctiInfo.className = 'opencti-info';

        const icon = document.createElement('span');
        icon.className = 'opencti-icon';

        if (!openctiData || openctiData.error) {
            icon.innerHTML = '❗';
            icon.title = 'OpenCTI data not available';
            openctiInfo.appendChild(icon);
            
            const errorMessage = document.createElement('span');
            errorMessage.className = 'opencti-error';
            errorMessage.textContent = 'OpenCTI data not available';
            openctiInfo.appendChild(errorMessage);
        } else {
            icon.innerHTML = openctiData.found ? '✅' : '❌';
            icon.title = openctiData.found ? 'Found in OpenCTI' : 'Not found in OpenCTI';
            openctiInfo.appendChild(icon);

            if (openctiData.found) {
                if (openctiData.labels && openctiData.labels.length > 0) {
                    const labels = document.createElement('span');
                    labels.className = 'opencti-labels';
                    labels.textContent = openctiData.labels.join(', ');
                    openctiInfo.appendChild(labels);
                }

                if (openctiData.id) {
                    const link = document.createElement('button');
                    link.textContent = 'Open in OpenCTI';
                    link.className = 'opencti-link';
                    link.addEventListener('click', () => {
                        backend.open_opencti_link(openctiData.id, function(response) {
                            const result = JSON.parse(response);
                            if (result.status !== 'success') {
                                console.error('Failed to open OpenCTI link:', result.message);
                                alert('Failed to open OpenCTI link. Please check the console for more information.');
                            }
                        });
                    });
                    openctiInfo.appendChild(link);
                }
            }
        }

        if (isOriginalDomain) {
            const domainNote = document.createElement('span');
            domainNote.className = 'domain-note';
            domainNote.textContent = ' (Domain data)';
            openctiInfo.appendChild(domainNote);
        }

        return openctiInfo;
    }

    function createReputationInfo(index) {
        const osintData = currentData.detailed_info[index].osint;
        const reputationInfo = document.createElement('div');
        reputationInfo.className = 'reputation-info';

        const reputationStatus = document.createElement('span');
        reputationStatus.className = `reputation-status ${getScoreClass(osintData.reputation.score)}`;
        reputationStatus.textContent = osintData.reputation.status;
        reputationInfo.appendChild(reputationStatus);

        return reputationInfo;
    }

    function showMoreInfo(index) {
        const info = currentData.detailed_info[index];
        const inputValue = info.original_domain || info.query;
        const dialogContent = `
            <h3>Detailed Information for ${inputValue}</h3>
            ${info.original_domain ? `<p><strong>Domain:</strong> ${info.original_domain}</p>` : ''}
            <p><strong>IP:</strong> ${info.query}</p>
            <p><strong>Country:</strong> ${info.country}</p>
            <p><strong>City:</strong> ${info.city}</p>
            <p><strong>Region:</strong> ${info.regionName}</p>
            <p><strong>ZIP:</strong> ${info.zip}</p>
            <p><strong>Latitude:</strong> ${info.lat}</p>
            <p><strong>Longitude:</strong> ${info.lon}</p>
            <p><strong>Timezone:</strong> ${info.timezone}</p>
            <p><strong>ISP:</strong> ${info.isp}</p>
            <p><strong>Organization:</strong> ${info.org}</p>
            <p><strong>AS:</strong> ${info.as}</p>
        `;
        showDialog(dialogContent);
    }

    function showDetailedReputation(index) {
        const osintData = currentData.detailed_info[index].osint;
        const dialogContent = `
            <h3>Detailed Reputation Information</h3>
            ${osintData.virustotal ? `
                <div class="osint-item">
                    <strong>VirusTotal:</strong> 
                    <span class="osint-score ${getScoreClass(osintData.virustotal.percentage)}">
                        ${osintData.virustotal.score} (${osintData.virustotal.percentage}%)
                    </span>
                </div>
            ` : ''}
            ${osintData.abuseipdb ? `
                <div class="osint-item">
                    <strong>AbuseIPDB:</strong> 
                    <span class="osint-score ${getScoreClass(osintData.abuseipdb.abuse_confidence_score)}">
                        ${osintData.abuseipdb.abuse_confidence_score}%
                    </span>
                </div>
            ` : ''}
            ${osintData.greynoise ? `
                <div class="osint-item">
                    <strong>GreyNoise:</strong> ${osintData.greynoise.classification}
                </div>
            ` : ''}
            ${osintData.ipqualityscore ? `
                <div class="osint-item">
                    <strong>IPQualityScore:</strong> 
                    <span class="osint-score ${getScoreClass(osintData.ipqualityscore.fraud_score)}">
                        ${osintData.ipqualityscore.fraud_score}
                    </span>
                    ${osintData.ipqualityscore.proxy ? '| Proxy' : ''}
                    ${osintData.ipqualityscore.vpn ? '| VPN' : ''}
                    ${osintData.ipqualityscore.tor ? '| TOR' : ''}
                </div>
            ` : ''}
        `;
        showDialog(dialogContent);
    }

    function performReverseLookup(ip) {
        backend.reverse_ip_lookup(ip, function(response) {
            const data = JSON.parse(response);
            let content;
            if (data.status === 'success') {
                content = `
                    <h3>Reverse DNS Lookup</h3>
                    <p><strong>IP:</strong> ${ip}</p>
                    <p><strong>Domains:</strong></p>
                    <ul>
                        ${data.domains.map(domain => `<li>${domain}</li>`).join('')}
                    </ul>
                `;
            } else {
                content = `
                    <h3>Reverse DNS Lookup</h3>
                    <p><strong>IP:</strong> ${ip}</p>
                    <p>Error: ${data.message}</p>
                `;
            }
            showDialog(content);
        });
    }

    function showDialog(content) {
        const dialog = document.createElement('div');
        dialog.className = 'dialog';
        dialog.innerHTML = `
            <div class="dialog-content">
                ${content}
                <button class="close-dialog">Close</button>
            </div>
        `;
        document.body.appendChild(dialog);

        dialog.querySelector('.close-dialog').addEventListener('click', () => {
            document.body.removeChild(dialog);
        });
    }

    function updateMap(mapData) {
        // Decode the base64-encoded map data
        const decodedMapData = atob(mapData);

        // Create a new iframe to display the map
        const iframe = document.createElement('iframe');
        iframe.srcdoc = decodedMapData;
        iframe.style.width = '100%';
        iframe.style.height = '600px';
        iframe.style.border = 'none';

        // Clear the map container and add the iframe
        elements.mapElement.innerHTML = '';
        elements.mapElement.appendChild(iframe);
    }

    function exportData(format) {
        if (!currentData || !currentData.detailed_info) {
            alert('No data to export. Please perform a search first.');
            return;
        }

        let exportFunction;
        switch (format) {
            case 'csv':
                exportFunction = exportCSV;
                break;
            case 'pdf':
                exportFunction = exportPDF;
                break;
            case 'stix':
                exportFunction = exportSTIX;
                break;
            default:
                alert('Invalid export format');
                return;
        }

        exportFunction();
    }

    function exportCSV() {
        backend.export_csv(JSON.stringify(currentData), function(response) {
            const data = JSON.parse(response);
            if (data.status === 'success') {
                alert('CSV file exported successfully: ' + data.filename);
            } else {
                alert('Error exporting CSV: ' + data.message);
            }
        });
    }

    function exportPDF() {
        backend.export_pdf(JSON.stringify(currentData), function(response) {
            const data = JSON.parse(response);
            if (data.status === 'success') {
                alert('PDF file exported successfully: ' + data.filename);
            } else if (data.status === 'cancelled') {
                console.log('PDF export cancelled by user');
            } else {
                alert('Error exporting PDF: ' + data.message);
            }
        });
    }

    function exportSTIX() {
        backend.export_stix(JSON.stringify(currentData), function(response) {
            const data = JSON.parse(response);
            if (data.status === 'success') {
                alert('STIX file exported successfully: ' + data.filename);
            } else if (data.status === 'cancelled') {
                console.log('STIX export cancelled by user');
            } else {
                alert('Error exporting STIX: ' + data.message);
            }
        });
    }

    function handleCSVUpload(event) {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                const content = e.target.result;
                const entries = processCSV(content);
                elements.ipInput.value = entries.join(', ');
                updateSearchButtonState();
            };
            reader.readAsText(file);
        }
    }

    function processCSV(content) {
        const lines = content.split('\n');
        const entries = lines.map(line => line.trim()).filter(line => {
            // Simple IP and domain validation regex
            return /^(\d{1,3}\.){3}\d{1,3}$/.test(line) || /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(line);
        });
        const uniqueEntries = [...new Set(entries)]; // Remove duplicates
        const limitedEntries = uniqueEntries.slice(0, 10); // Limit to 10 entries
        
        if (limitedEntries.length < uniqueEntries.length) {
            alert(`Only the first 10 valid and unique entries have been added. ${uniqueEntries.length - limitedEntries.length} entry(ies) were omitted.`);
        }
        
        if (limitedEntries.length === 0) {
            alert('No valid IP addresses or domain names found in the CSV file.');
        } else {
            alert(`${limitedEntries.length} valid entry(ies) have been added to the input field.`);
        }
        
        return limitedEntries;
    }

    function toggleApiKeyVisibility(key) {
        backend.toggle_api_key_visibility(key, function(response) {
            const data = JSON.parse(response);
            if (data.status === 'success') {
                const input = document.getElementById(`${key}-api-key`);
                const button = document.getElementById(`${key}-api-key-toggle`);
                if (input && button) {
                    input.value = data.value;
                    button.textContent = data.value.includes('*') ? 'Show' : 'Hide';
                }
            } else {
                console.error('Error toggling API key visibility:', data.message);
            }
        });
    }

    // Initialize
    updateSearchButtonState();
    toggleExportButtons(false);

    // Add event listener for settings form submission
    document.getElementById('settings-form').addEventListener('submit', function(event) {
        event.preventDefault();
        
        if (!isVisible) {
            alert('Please show all API keys before saving settings.');
            return;
        }
        
        const apiKeys = {
            vt: document.getElementById('vt-api-key').value,
            abuseipdb: document.getElementById('abuseipdb-api-key').value,
            greynoise: document.getElementById('greynoise-api-key').value,
            ipqualityscore: document.getElementById('ipqualityscore-api-key').value,
            opencti: document.getElementById('opencti-api-key').value
        };
        
        const openctiUrl = document.getElementById('opencti-url').value;
        
        backend.update_api_settings(JSON.stringify({apiKeys, openctiUrl}), function(response) {
            const data = JSON.parse(response);
            if (data.status === 'success') {
                alert('API settings updated successfully.');
                // Update input values after successful save
                updateInputValues();
            } else {
                alert('Error updating API settings: ' + data.message);
            }
        });
    });

    const toggleVisibilityButton = document.getElementById('toggle-api-visibility');
    const apiInputs = document.querySelectorAll('#settings-form input[type="password"]');
    const saveSettingsButton = document.getElementById('settings-form').querySelector('button[type="submit"]');
    let isVisible = false;

    function updateSaveButtonState() {
        saveSettingsButton.disabled = !isVisible;
    }

    toggleVisibilityButton.addEventListener('click', function() {
        isVisible = !isVisible;
        apiInputs.forEach(input => {
            const inputName = input.name === 'opencti-url' ? 'opencti-url' : input.name.replace('-api-key', '');
            backend.toggle_api_key_visibility(inputName, function(response) {
                const data = JSON.parse(response);
                if (data.status === 'success') {
                    input.value = data.value;
                    input.type = isVisible ? 'text' : 'password';
                }
            });
        });
        this.textContent = isVisible ? 'Hide All' : 'Show All';
        updateSaveButtonState();
    });

    // Update save button state on page load
    updateSaveButtonState();

    // Add this new function to update input values after saving
    function updateInputValues() {
        apiInputs.forEach(input => {
            const inputName = input.name === 'opencti-url' ? 'opencti-url' : input.name.replace('-api-key', '');
            backend.toggle_api_key_visibility(inputName, function(response) {
                const data = JSON.parse(response);
                if (data.status === 'success') {
                    input.value = data.value;
                }
            });
        });
    }
});