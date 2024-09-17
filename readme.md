# 🌐 IOC Information

IOC Information is a tool designed for efficient IP and domain lookups, primarily for use by cyber threat intelligence analysts. It provides comprehensive information about network entities, leveraging multiple data sources and APIs. This application was developed with assistance from CursorAI to enhance functionality and code quality.

## 🚀 Features

### 🔍 Multi-Entity Lookup
- Simultaneous lookup for up to 10 IP addresses or domain names
- Support for IPv4, IPv6 addresses, and domain names including escaped values

### 🗺️ Geolocation Visualization
- Interactive global map with color-coded markers
- Detailed geographic information (country, city, region)

### 🛡️ Threat Intelligence Integration
- Reputation analysis from multiple sources (VirusTotal, AbuseIPDB, GreyNoise, IPQualityScore)
- OpenCTI integration for advanced threat intelligence
- Direct link to OpenCTI dashboard

### 🌐 Network Information
- ISP and organization details
- AS number
- Timezone
- Reverse DNS lookup for IP addresses

### 📊 Data Enrichment
- Related articles fetched via Bing Search API
- Customized search queries for result relevance

### 📤 Export Capabilities
- CSV export for spreadsheet analysis
- PDF export for reporting
- STIX export for threat intelligence sharing

### 📥 Data Import
- CSV file upload for bulk IP/domain processing

### ⚙️ Customization
- Configurable API settings
- Adjustable OpenCTI URL

### 🖥️ User Interface
- Dark mode toggle
- AI-generated result summaries using OpenAI's GPT model

## 🛠️ Setup

1. Ensure Python is installed on your system.

2. Clone the repository:
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

4. Configure API keys:
   - Copy `config.example.py` to `config.py`
   - Replace placeholder API keys in `config.py` with valid keys

5. Launch the application:
   ```
   python main.py
   ```

## 📋 Usage

1. Input IP addresses or domain names (comma-separated for multiple entries)
2. Initiate lookup
3. View results on the map and in the detailed panel
4. Utilize additional features (More Info, Detailed Reputation, Reverse DNS)
5. Generate AI-powered summary of results
6. Export results as needed
7. Toggle dark mode as preferred

## 🔑 Required API Keys

The following API keys are required for full functionality:

- VirusTotal
- AbuseIPDB
- GreyNoise
- IPQualityScore
- OpenCTI
- Bing Search
- OpenAI

Configure these keys in the application's Settings panel.


## Examples
- Example 1
![example_1](https://github.com/user-attachments/assets/4fcf8312-2246-4cb6-b859-ba9bb596abd9)
- Example 2
![example_2](https://github.com/user-attachments/assets/248a21b9-1543-4c9e-82b8-e9addeb9f278)
- Example 3
![example_3](https://github.com/user-attachments/assets/7097c376-2ce6-4ff0-934d-ee52d077b100)
- Example 4
![example_4](https://github.com/user-attachments/assets/c2edd99e-ac8a-4bbd-9a7e-cd649407ac31)
