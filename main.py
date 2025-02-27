from scanner.active import get_active_connections
from scanner.past import get_past_connections
from scanner.threat_intel import check_ip_abuse
import json
from datetime import datetime
import sys
import platform
import psutil
import tkinter as tk
from ui.gui import ThreatScannerUI
import argparse
from tkinter import ttk
import logging
import ipaddress
from ttkthemes import ThemedTk

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("main.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("main")

def check_permissions():
    """Check if script has necessary permissions"""
    try:
        # Try to get a small sample of connections to test permissions
        psutil.net_connections(kind='inet')[:1]
        return True
    except (psutil.AccessDenied, PermissionError):
        current_os = platform.system()
        message = "\nError: Insufficient permissions!\n"
        message += "This tool needs elevated privileges to access network information.\n\n"
        message += "Please run as:\n"
        if current_os in ('Darwin', 'Linux'):
            message += "    sudo -E python main.py"
        elif current_os == 'Windows':
            message += "    Run as Administrator"
        return message

def scan_network(ip_list=None, service='all'):
    """Scan IPs for threat intelligence."""
    logger.info(f"Scanning network with service: {service}")
    
    # If no IPs provided, get active and past connections
    if not ip_list:
        try:
            # Get IPs from active connections
            active_ips = get_active_connections()
            # Get IPs from system logs
            past_ips = get_past_connections()
            
            # Combine and remove duplicates
            ip_list = list(set(active_ips + past_ips))
            
            if ip_list:
                logger.info(f"Collected {len(ip_list)} IPs from system ({len(active_ips)} active, {len(past_ips)} from logs)")
            else:
                # Fallback to localhost if no connections found
                ip_list = ['127.0.0.1']
                logger.info("No connections found, defaulting to localhost")
        except Exception as e:
            # If there's an error collecting IPs, fallback to localhost
            ip_list = ['127.0.0.1']
            logger.error(f"Error collecting system connections: {str(e)}")
            logger.info("Defaulting to localhost")
    
    # Query each IP against the selected threat intelligence services
    results = {}
    for ip in ip_list:
        logger.info(f"Checking IP: {ip}")
        try:
            # Validate IP
            ipaddress.ip_address(ip)
            # Get threat intel
            results[ip] = check_ip_abuse(ip, service=service)
        except ValueError as e:
            logger.error(f"Invalid IP address: {ip}")
            results[ip] = {'source': service, 'error': f"Invalid IP format: {str(e)}"}
        except Exception as e:
            logger.error(f"Error checking {ip}: {str(e)}", exc_info=True)
            results[ip] = {'source': service, 'error': str(e)}
    
    return results

def cli_scan(ip_list, service='all', json_output=False):
    """Command-line interface for scanning IPs."""
    results = scan_network(ip_list, service)
    
    if json_output:
        # Output results as JSON
        print(json.dumps(results, indent=2))
    else:
        # Pretty print results
        for ip, result in results.items():
            print(f"\n===== Results for {ip} =====")
            
            if 'error' in result:
                print(f"ERROR: {result['error']}")
                continue
                
            if result['source'] == 'all':
                # Process AbuseIPDB results
                if 'error' in result['abuseipdb']:
                    print(f"AbuseIPDB: Error - {result['abuseipdb']['error']}")
                else:
                    abuse_data = result['abuseipdb'].get('data', {})
                    print(f"AbuseIPDB Score: {abuse_data.get('abuseConfidenceScore', 0)}%")
                    print(f"Country: {abuse_data.get('countryCode', 'N/A')}")
                    print(f"ISP: {abuse_data.get('isp', 'Unknown')}")
                
                # Process VirusTotal results
                if 'error' in result['virustotal']:
                    print(f"VirusTotal: Error - {result['virustotal']['error']}")
                else:
                    vt_data = result['virustotal'].get('data', {})
                    malicious = vt_data.get('malicious', 0)
                    suspicious = vt_data.get('suspicious', 0)
                    harmless = vt_data.get('harmless', 0)
                    undetected = vt_data.get('undetected', 0)
                    total = malicious + suspicious + harmless + undetected
                    
                    print(f"VirusTotal Stats: {malicious} malicious, {suspicious} suspicious, {harmless} harmless, {undetected} undetected")
                    if total > 0:
                        print(f"VirusTotal Score: {round((malicious + suspicious) / total * 100)}% ({malicious}/{total})")
                
                # Process AlienVault results
                if 'error' in result['alienvault']:
                    print(f"AlienVault: Error - {result['alienvault']['error']}")
                else:
                    av_data = result['alienvault'].get('data', {})
                    pulse_count = av_data.get('pulse_count', 0)
                    threat_score = av_data.get('threat_score', 0)
                    malware_samples = av_data.get('malware_samples', 0)
                    url_count = av_data.get('url_count', 0)
                    dns_count = av_data.get('dns_count', 0)
                    
                    print(f"AlienVault Pulse Count: {pulse_count} reports")
                    print(f"AlienVault Threat Score: {threat_score}%")
                    
                    # Print additional insight data
                    print(f"AlienVault Malware Samples: {malware_samples}")
                    print(f"AlienVault Associated URLs: {url_count}")
                    print(f"AlienVault DNS Records: {dns_count}")
                    
                    # Print country info
                    country = av_data.get('country_name', 'N/A')
                    if country != 'N/A':
                        print(f"AlienVault Location: {country} ({av_data.get('city', 'N/A')})")
                    
                    # Print tags if available
                    tags = av_data.get('tags', [])
                    if tags:
                        print(f"AlienVault Tags: {', '.join(tags)}")
                    
                    # Print malware families if available
                    malware_families = av_data.get('malware_families', [])
                    if malware_families:
                        print(f"AlienVault Malware Families: {', '.join(malware_families)}")
                    
                    # Print sample URL if available
                    urls = av_data.get('associated_urls', [])
                    if urls:
                        print(f"AlienVault Sample URL: {urls[0]}")
                    
                    # Print sample DNS record if available
                    dns_records = av_data.get('dns_records', [])
                    if dns_records:
                        print(f"AlienVault Sample DNS: {dns_records[0]['hostname']} ({dns_records[0]['record_type']})")
                    
                    # Print additional info reminder
                    if pulse_count > 0 or malware_samples > 0 or url_count > 0 or dns_count > 0:
                        print("Use GUI mode for complete AlienVault OTX details")
                
            elif result['source'] == 'both':
                # Similar handling for both services...
                pass
            else:
                # Handle single service results...
                pass

def has_tkinter():
    try:
        import tkinter
        return True
    except ImportError:
        return False

def gui_mode():
    """Run in GUI mode"""
    try:
        try:
            # Try using ThemedTk with equilux theme
            root = ThemedTk(theme="equilux")
            logger.info("Using ThemedTk with equilux theme")
        except Exception as e:
            # Fall back to standard Tk if ThemedTk fails
            logger.warning(f"Could not initialize ThemedTk: {str(e)}")
            logger.info("Falling back to standard Tk")
            root = tk.Tk()
            style = ttk.Style()
            try:
                style.theme_use('clam')  # Try to use clam theme as fallback
                logger.info("Using ttk clam theme")
            except tk.TclError:
                logger.warning("Could not use clam theme, using default theme")
                # Continue with default theme
            
        app = ThreatScannerUI(root, scanner_callback=scan_network)
        root.mainloop()
    except Exception as e:
        logger.error(f"Error starting GUI: {str(e)}", exc_info=True)
        print(f"Error starting GUI: {str(e)}")
        print("Falling back to CLI mode...")
        cli_scan(['127.0.0.1'], 'all')

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Network Threat Scanner")
    parser.add_argument('--debug', action='store_true', help='Run in debug/CLI mode')
    parser.add_argument('--ip', nargs='+', help='IP addresses to scan')
    parser.add_argument('--service', choices=['all', 'both', 'abuseipdb', 'virustotal', 'alienvault'], 
                        default='all', help='Threat intelligence service to use')
    parser.add_argument('--json', action='store_true', help='Output results as JSON (CLI mode only)')
    args = parser.parse_args()
    
    # Set up logging level based on debug mode
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("Debug mode enabled")
    else:
        logging.getLogger().setLevel(logging.INFO)
    
    # If in debug/CLI mode, or IPs specified, run CLI scan
    if args.debug or args.ip:
        # Use CLI mode
        cli_scan(args.ip, args.service, args.json)
    else:
        # Use GUI mode
        try:
            # Try using ThemedTk with equilux theme
            root = ThemedTk(theme="equilux")
            logger.info("Using ThemedTk with equilux theme")
        except Exception as e:
            # Fall back to standard Tk if ThemedTk fails
            logger.warning(f"Could not initialize ThemedTk: {str(e)}")
            logger.info("Falling back to standard Tk")
            root = tk.Tk()
            style = ttk.Style()
            try:
                style.theme_use('clam')  # Try to use clam theme as fallback
                logger.info("Using ttk clam theme")
            except tk.TclError:
                logger.warning("Could not use clam theme, using default theme")
                # Continue with default theme
                
        app = ThreatScannerUI(root, scanner_callback=scan_network)
        root.mainloop()

if __name__ == "__main__":
    main() 