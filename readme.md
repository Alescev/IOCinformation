# IP Geolocation Explorer

IP Geolocation Explorer is a user-friendly tool that helps you learn more about IP addresses and domain names. It shows you where they're located on a map and gives you information about their reputation and potential security risks.

## What Can It Do?

- Look up information for up to 10 IP addresses or domain names at once
- Show locations on an interactive map
- Provide safety scores from trusted sources
- Connect with threat intelligence databases
- Save your results in different file formats
- Upload a list of addresses from a file

## Getting Started

1. Make sure you have Python installed on your computer.

2. Download or clone this project to your computer.

3. Open a command prompt or terminal in the project folder.

4. Set up the project by running these commands:
   ```
   python -m venv .venv
   .venv\Scripts\activate  # On Windows
   source .venv/bin/activate  # On Mac/Linux
   pip install -r requirements.txt
   ```

5. Look for the `config.example.py` file in the main folder. Make a copy of it and name the copy `config.py`.

6. Open `config.py` and replace the example API keys with your own. You'll need to sign up for free accounts at VirusTotal, AbuseIPDB, GreyNoise, IPQualityScore, and OpenCTI to get these keys.

## Using the Tool

To start the application, run: 
 ```
python main.py
 ```
Type in the IP addresses or domain names you want to look up, separated by commas. Click "Search" to see the results. You can save your results using the export buttons.


