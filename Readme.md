# Network Threat Scanner

Cross-platform application with GUI to detect and analyse potentially malicious IP connections using multiple threat intelligence sources and AI-powered analysis.

## Features
- Interactive GUI interface with real-time scanning
- Comprehensive threat intelligence from multiple sources:
  - AbuseIPDB integration
  - VirusTotal integration
  - AlienVault OTX integration
- AI-powered analysis using Google's Gemini AI
- Historical log analysis
- Custom IP list scanning
- Detailed threat reports with confidence scores
- Direct links to threat intelligence platforms
- Export capabilities for further analysis

## Requirements
- Python 3.8+
- Administrator/sudo privileges for log access
- Tkinter support for GUI
- API Keys (all free):
  - AbuseIPDB API key
  - VirusTotal API key
  - AlienVault OTX API key
  - Google Gemini AI API key

## Installation

### 1. Install Python Dependencies

#### Windows:
Python usually comes with Tkinter. If missing:
1. Download Python from [Python.org](https://python.org)
2. During installation, ensure "tcl/tk and IDLE" is selected

#### macOS:
```bash
# Install Python with Tkinter support
brew install python-tk

# If using Python 3.13 specifically
brew install python-tk@3.13
```

#### Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install python3-tk
```

#### CentOS/RHEL:
```bash
sudo yum install python3-tkinter
```

### 2. Setup Project

1. Clone the repository:
```bash
git clone <repository-url>
cd network_threat_scanner
```

2. Create virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

### 3. Configure API Keys

1. Create a `.env` file in the project root:
```bash
touch .env
```

2. Add your API keys to `.env`:
```plaintext
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
ALIENVAULT_API_KEY=your_alienvault_key_here
GEMINI_API_KEY=your_gemini_key_here
```

## Usage

### GUI Mode (Default)

#### Starting the Application

#### Windows:
1. Open PowerShell as Administrator
2. Navigate to project directory
3. Run:
```powershell
.\venv\Scripts\activate
python main.py
```

#### macOS/Linux:
```bash
source venv/bin/activate
sudo -E python main.py
```
The `-E` flag is important as it preserves environment variables (including your API keys)

#### Using the Interface

1. **IP Scanning Options**
   - **System Scan**: Click "Start New Scan" to analyse current connections
   - **Custom IP List**: 
     - Click "Upload IP List" to scan specific IPs
     - Supported format: Text file with one IP per line
     - Click "Clear IP List" to remove loaded IPs

2. **Results Table**
   - Displays scan results in real-time
   - Columns:
     - IP Address
     - AbuseIPDB Score
     - VirusTotal Score
     - AlienVault Score
     - Country
     - ISP

3. **Actions**
   - **View Details**: Complete information for selected IP
   - **Open in AbuseIPDB**: View IP in AbuseIPDB database
   - **Open in VirusTotal**: View IP in VirusTotal database
   - **Open in AlienVault**: View IP in AlienVault OTX database
   - **Export Results**: Save scan results as JSON
   - **AI Analysis**: Get Gemini AI insights about threats

4. **AI Analysis Features**
   - Click "AI Analysis" to get:
     - Key security insights
     - Risk assessment for each IP
     - Recommended actions
     - Pattern identification
   - Ask follow-up questions for clarification
   - Export AI analysis reports

### CLI Mode

The application also supports command-line operation for scripting or server environments:

```bash
# Run in CLI/debug mode
python main.py --debug

# Scan specific IP addresses
python main.py --ip 8.8.8.8 1.1.1.1

# Output results as JSON
python main.py --ip 8.8.8.8 --json
```

#### CLI Options:
- `--debug`: Run in debug/CLI mode with detailed logging
- `--ip [IPs]`: Space-separated list of IP addresses to scan
- `--service`: Specify service to use (all, both, abuseipdb, virustotal, alienvault)
- `--json`: Output results in JSON format instead of text


## Output Formats

### JSON Report Structure
```json
{
  "timestamp": "YYYYMMDD_HHMMSS",
  "scan_results": {
    "ip_address": {
      "source": "all",
      "abuseipdb": {
        // AbuseIPDB-specific threat data
      },
      "virustotal": {
        // VirusTotal-specific threat data
      },
      "alienvault": {
        // AlienVault-specific threat data
      }
    }
  },
  "ai_analysis": {
    "insights": "",
    "risk_assessment": "",
    "recommendations": ""
  }
}
```

## Troubleshooting

### GUI Not Starting
1. Verify Tkinter installation:
```python
python -c "import tkinter; tkinter._test()"
```
If this fails, reinstall Tkinter using the instructions above.

2. Theme issues:
The application will attempt to use the 'equilux' theme, with fallbacks to 'clam' and finally the default theme if neither is available.

### Permission Errors
- Windows: Ensure running PowerShell as Administrator
- macOS/Linux: Use `sudo -E` to preserve environment variables

### API Errors
1. Check `.env` file exists in project root
2. Verify API keys are correct
3. Ensure no spaces around the API keys in `.env`

### AI Analysis Issues
1. Verify GEMINI_API_KEY in .env
2. Check internet connectivity
3. Ensure input data is properly formatted

### Rate Limits
- AbuseIPDB: 1000 requests/day (free tier)
- VirusTotal: 4 requests/minute (free tier)
- AlienVault OTX: 1000 requests/day (free tier)
- Gemini AI: 60 requests/minute

## Security and Privacy Notes
- All API calls are made using HTTPS
- No data is stored externally
- Reports are saved locally only
- Review code before running with elevated privileges

## Support and Contribution
For issues or questions:
1. Check the troubleshooting section
2. Verify all installation steps
3. Create an issue in the repository

## License
This project is licensed under the terms of the [MIT License](./LICENSE).


## Things i would like to work on

### Optimizations and Performance
- [ ] Multi-threading for parallel IP scanning
- [ ] Batch API requests to reduce network overhead
- [ ] Local caching mechanism for recent scan results
- [ ] Memory optimization for large IP datasets
- [ ] Progressive loading for large result sets
- [ ] Background scanning with task prioritisation
- [ ] Smart API request throttling to respect rate limits
- [ ] Lightweight mode for resource-constrained environments

### Scanning and Detection
- [ ] Support for IPv6 addresses
- [ ] Automated periodic scanning capability
- [ ] Network-wide scanning for internal networks
- [ ] Integration with additional threat intelligence sources
- [ ] Customizable threat scoring algorithm

### User Interface
- [ ] Dark mode UI theme
- [ ] Customizable dashboard and layouts
- [ ] Advanced filtering options for scan results
- [ ] Network visualization of threat origins
- [ ] Interactive world map of detected threats

### Reporting and Alerts
- [ ] Multiple export formats (CSV, PDF, HTML)
- [ ] Email notifications for critical threats
- [ ] Scheduled report generation
- [ ] Executive summary reports
- [ ] Trend analysis for recurring threats

### Advanced Features
- [ ] Firewall rule generation based on threat findings
- [ ] Custom IP whitelisting and blacklisting
- [ ] Database integration for historical tracking
- [ ] REST API for integration with other security tools
- [ ] Browser extension for quick IP lookup

### Platform Support
- [ ] Standalone executable packages
- [ ] Docker containerization
- [ ] Mobile companion app for alerts
- [ ] Installer for easier deployment



