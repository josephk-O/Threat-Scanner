# Network Threat Scanner

Threat Scanner is a cross-platform Python application that helps investigate potentially malicious IP activity. It combines live network inspection, historical log review, and third-party threat-intelligence feeds inside an approachable Tkinter UI, with a CLI for automation.

## Highlights

- Multi-source threat enrichment (AbuseIPDB, VirusTotal, AlienVault OTX)
- Responsive desktop UI with background scanning, progress dialog, and overflow menu for actions
- AI-assisted reporting powered by Google Gemini to generate security insights and answer follow-up questions
- Structured logging with rotating files and consistent scan telemetry
- Parallel scanning with rate-limited API access to respect free-tier quotas
- Exportable JSON reports for downstream analysis

## Tech Stack

- **Python** 3.8+
- **Tkinter** + `ttkthemes`
- **ThreadPoolExecutor** for parallel scans
- **Requests** for HTTP APIs
- **dotenv** for runtime configuration
- **Custom logging handlers** (see `handlers/threat_logging.py`)

## Project Structure

```
Threat-Scanner/
├── handlers/            # Logging helpers
├── logs/                # Rotating log files
├── scanner/             # Core scanning + AI modules
├── ui/                  # Tkinter UI implementation
├── main.py              # Entry point (GUI/CLI)
├── requirements.txt     # Python dependencies
└── Readme.md
```

## Getting Started

### 1. Clone & Create Virtual Environment

```bash
git clone <repository-url>
cd Threat-Scanner

python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Keys

Create a `.env` file in the project root:

```bash
touch .env
```

Add your keys (free tiers are sufficient while testing):

```dotenv
ABUSEIPDB_API_KEY=...
VIRUSTOTAL_API_KEY=...
ALIENVAULT_API_KEY=...
GEMINI_API_KEY=...
```

### 4. Platform Notes

- **Windows**: run PowerShell as Administrator before launching the app.
- **macOS / Linux**: Tkinter comes with most Python installs; if missing, install `python-tk` via Homebrew or your package manager. When running with elevated privileges, use `sudo -E` so environment variables (API keys) survive.

## Running the Application

### GUI (default)

```bash
python main.py
```

What to expect:

1. **Start New Scan** – collects active sockets and historical connections, deduplicates, and runs a threat check per IP.
2. **Progress dialog** – scanning happens on a background thread; the UI stays responsive and shows real-time status.
3. **Results table** – one row per IP with scores from AbuseIPDB, VirusTotal, and AlienVault plus location metadata.
4. **Action bar** – primary actions remain on the first row; overflow items move into a `More…` menu if the window is narrow.
5. **AI report** – use “AI security report” to generate a Gemini summary and ask follow-up questions in a dedicated dialog.

### CLI Examples

```bash
# Scan specific IPs and print summary
python main.py --ip 8.8.8.8 1.1.1.1

# JSON output for automation
python main.py --ip 8.8.8.8 --json

# Use a specific provider only
python main.py --ip 8.8.8.8 --service virustotal
```

CLI mode shares the same logging infrastructure and parallel scanning logic as the GUI. Progress bars auto-adjust to the number of targets collected during runtime.

## Configuration & Logging

- Logs are written to `logs/<service>.log` with rotation (10 MB × 5 files).
- Log levels can be changed via `ThreatScanLogger.set_level` if needed.
- `scanner/threat_intel.py` centralises API rate limits and normalises responses.

## Testing & Quality

- Static compilation check:

  ```bash
  python -m compileall handlers/threat_logging.py scanner/threat_intel.py ui/gui.py
  ```

- API calls require valid credentials; use sandbox/test IPs when exercising the code.

## Quick Troubleshooting

| Issue | Fix |
|-------|-----|
| GUI fails to open | Verify Tkinter installation (`python -c "import tkinter; tkinter._test()"`). |
| Permission errors on macOS/Linux | Run with `sudo -E python main.py`. |
| API quota exceeded | Reduce concurrency or wait for the provider reset; free tiers have strict limits. |
| Partial buttons in action bar | Resize window or use the `More…` dropdown (responsive layout is enabled). |

## Roadmap

- Batch lookups and caching of repeated IPs
- Additional intelligence sources (e.g., Shodan, GreyNoise)
- Improved reporting (CSV/PDF exports, scheduled jobs)
- Enhanced visualisation (maps, trend charts)

## License

MIT License – see [LICENSE](./LICENSE) for full details.

## Contributing & Feedback

This project is actively iterated on. If you spot bugs or have feature ideas:

1. Open an issue with reproduction steps and log snippets where possible.
2. Fork, create a feature branch, and submit a pull request.
3. Tag improvements with the roadmap categories above to keep things organised.

Happy scanning!
