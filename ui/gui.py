import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from ttkthemes import ThemedTk
import json
import logging
import webbrowser
from datetime import datetime
from scanner.threat_intel import check_ip_abuse
from scanner.ai_analysis import analyze_results, get_clarification

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("gui.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("gui")

class ThreatScannerUI:
    def __init__(self, master, scanner_callback=None):
        self.master = master
        self.scanner_callback = scanner_callback
        self.data = {}
        self.current_service = tk.StringVar(value='all')  # Default to all services
        self.ip_list = []
        self.analysis_window = None
        
        logger.info("Initializing ThreatScannerUI")
        
        master.title("Network Threat Scanner")
        master.geometry("800x600")
        
        # Configure styles with a better theme
        style = ttk.Style()
        try:
            style.theme_use('equilux')  # Match the theme from main.py
            logger.info("Using equilux theme for UI")
        except tk.TclError as e:
            logger.warning(f"Could not use equilux theme: {str(e)}")
            try:
                style.theme_use('clam')  # Fallback theme if equilux isn't available
                logger.info("Using clam theme for UI")
            except tk.TclError as e:
                logger.warning(f"Could not use clam theme: {str(e)}")
                logger.info("Using default theme for UI")
                # Continue with default theme
        
        # Build UI
        self._build_header()
        self._build_ip_input()
        self._build_results_table()
        self._build_action_panel()

    def _build_header(self):
        header = ttk.Frame(self.master)
        ttk.Label(
            header, 
            text="Network Threat Scanner", 
            font=('Helvetica', 14, 'bold')
        ).pack(pady=10)
        
        # Scan button
        ttk.Button(
            header,
            text="Start New Scan",
            command=self._start_scan
        ).pack(pady=5)
        
        # Service information label
        ttk.Label(
            header, 
            text="Using AbuseIPDB, VirusTotal, and AlienVault OTX for comprehensive threat intelligence",
            font=('Helvetica', 10, 'italic')
        ).pack(pady=5)
        
        # Stats summary
        self.stats_label = ttk.Label(header, text="Ready to scan")
        self.stats_label.pack()
        header.pack(fill=tk.X)

    def _build_ip_input(self):
        """Build IP input section"""
        frame = ttk.Frame(self.master)
        
        # File upload button
        ttk.Button(
            frame,
            text="Upload IP List",
            command=self._upload_ip_list
        ).pack(side=tk.LEFT, padx=5)
        
        # IP list status
        self.ip_status = ttk.Label(frame, text="No IP list loaded")
        self.ip_status.pack(side=tk.LEFT, padx=5)
        
        # Clear IP list button
        ttk.Button(
            frame,
            text="Clear IP List",
            command=self._clear_ip_list
        ).pack(side=tk.LEFT, padx=5)
        
        frame.pack(pady=5)

    def _build_results_table(self):
        container = ttk.Frame(self.master)
        
        # Table columns
        columns = ('ip', 'abuseipdb_score', 'virustotal_score', 'alienvault_score', 'country', 'isp')
        self.table = ttk.Treeview(
            container, 
            columns=columns,
            show='headings',
            selectmode='browse'
        )
        
        # Configure columns
        self.table.heading('ip', text='IP Address')
        self.table.heading('abuseipdb_score', text='AbuseIPDB Score')
        self.table.heading('virustotal_score', text='VirusTotal Score')
        self.table.heading('alienvault_score', text='AlienVault Score')
        self.table.heading('country', text='Country')
        self.table.heading('isp', text='ISP')
        
        # Set column widths
        self.table.column('ip', width=120)
        self.table.column('abuseipdb_score', width=100)
        self.table.column('virustotal_score', width=100)
        self.table.column('alienvault_score', width=100)
        self.table.column('country', width=80)
        self.table.column('isp', width=150)
        
        # Double-click event to show details
        self.table.bind("<Double-1>", lambda event: self._show_details())
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.table.yview)
        self.table.configure(yscroll=scrollbar.set)
        
        # Pack components
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _build_action_panel(self):
        """Build the action panel with buttons"""
        panel = ttk.Frame(self.master)
        
        # Export button
        ttk.Button(
            panel,
            text="Export Results",
            command=self._export_results
        ).pack(side=tk.LEFT, padx=5)
        
        # View Details button
        ttk.Button(
            panel,
            text="View Details",
            command=self._show_details
        ).pack(side=tk.LEFT, padx=5)
        
        # AbuseIPDB button
        ttk.Button(
            panel,
            text="Open in AbuseIPDB",
            command=self._open_abuseipdb
        ).pack(side=tk.LEFT, padx=5)
        
        # VirusTotal button
        ttk.Button(
            panel,
            text="Open in VirusTotal",
            command=self._open_virustotal
        ).pack(side=tk.LEFT, padx=5)
        
        # AlienVault button
        ttk.Button(
            panel,
            text="Open in AlienVault",
            command=self._open_alienvault
        ).pack(side=tk.LEFT, padx=5)
        
        # AI Analysis button
        ttk.Button(
            panel,
            text="AI security report",
            command=self._show_ai_analysis
        ).pack(side=tk.LEFT, padx=5)
        
        # Debug button
        ttk.Button(
            panel,
            text="Debug Data",
            command=self._debug_data
        ).pack(side=tk.LEFT, padx=5)
        
        panel.pack(pady=10)

    def _upload_ip_list(self):
        """Handle IP list file upload"""
        filename = filedialog.askopenfilename(
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    # Read IPs and filter empty lines and invalid IPs
                    ips = [ip.strip() for ip in f.readlines()]
                    valid_ips = [ip for ip in ips if self._is_valid_ip(ip)]
                    self.ip_list = valid_ips
                    self.ip_status.config(
                        text=f"Loaded {len(valid_ips)} IPs from file"
                    )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load IP list: {str(e)}")

    def _clear_ip_list(self):
        """Clear loaded IP list"""
        self.ip_list = []
        self.ip_status.config(text="No IP list loaded")

    def _is_valid_ip(self, ip):
        """Validate IP address format"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except (AttributeError, TypeError, ValueError):
            return False

    def _start_scan(self):
        if not self.scanner_callback:
            messagebox.showerror("Error", "Scanner not initialized!")
            return
            
        try:
            service = self.current_service.get()
            logger.info(f"Starting scan with service: {service}")
            
            # Update stats label to show scanning status
            self.stats_label.config(text="Scanning...")
            
            # Create progress window
            progress_win = tk.Toplevel(self.master)
            progress_win.title("Scanning...")
            progress_win.geometry("300x150")
            
            # Add progress label
            progress_label = ttk.Label(progress_win, text="Scanning IP addresses...")
            progress_label.pack(pady=10)
            
            # Add progress bar
            progress_var = tk.DoubleVar()
            progress_bar = ttk.Progressbar(
                progress_win,
                variable=progress_var,
                maximum=100,
                mode='determinate'
            )
            progress_bar.pack(fill=tk.X, padx=20, pady=10)
            
            # Add status label
            status_label = ttk.Label(progress_win, text="Initializing scan...")
            status_label.pack(pady=10)
            
            # Update progress bar and status
            def update_progress(current, total, ip=None):
                if progress_win.winfo_exists():
                    progress = (current / total) * 100
                    progress_var.set(progress)
                    status_text = f"Scanning {ip}..." if ip else f"Completed {current}/{total} IPs"
                    status_label.config(text=status_text)
                    logger.info(status_text)
                    progress_win.update()
            
            # Run scan in a separate thread to prevent GUI freezing
            def run_scan():
                try:
                    logger.info("Starting scan thread")
                    ip_count = len(self.ip_list) if self.ip_list else 1
                    current = 0
                    
                    def progress_callback(ip):
                        nonlocal current
                        current += 1
                        update_progress(current, ip_count, ip)
                    
                    # Pass both IP list and selected service to scanner
                    logger.info(f"Scanning {ip_count} IPs with {service} service")
                    scan_data = self.scanner_callback(
                        self.ip_list if self.ip_list else None,
                        service=service,
                        max_workers=10
                    )
                    
                    # Extract results and stats
                    self.data = scan_data['results']
                    stats = scan_data['stats']
                    
                    # Update stats label with collection information
                    self.master.after(0, lambda: self.stats_label.config(text=stats['message']))
                    
                    logger.info("Scan completed successfully")
                    
                    # Update UI with results
                    self.master.after(0, self._update_table)
                    self.master.after(100, progress_win.destroy)
                    
                except Exception as e:
                    logger.error(f"Error during scan: {str(e)}", exc_info=True)
                    self.master.after(0, lambda: messagebox.showerror("Error", str(e)))
                    self.master.after(0, progress_win.destroy)
                    self.master.after(0, lambda: self.stats_label.config(text="Scan failed"))
            
            # Start scan thread
            import threading
            scan_thread = threading.Thread(target=run_scan)
            scan_thread.daemon = True
            logger.info("Starting scan in background thread")
            scan_thread.start()
            
        except Exception as e:
            logger.error(f"Error during scan setup: {str(e)}", exc_info=True)
            messagebox.showerror("Error", str(e))
            self.stats_label.config(text="Scan failed")

    def _process_abuseipdb_result(self, result):
        """Process AbuseIPDB result and return score string."""
        logger.debug(f"Processing AbuseIPDB result: {json.dumps(result, indent=2)}")
        if 'error' in result:
            logger.warning(f"AbuseIPDB error: {result['error']}")
            return "Error: Check API key"
        data = result.get('data', {})
        score = f"{data.get('abuseConfidenceScore', 0)}%"
        logger.debug(f"AbuseIPDB score: {score}")
        return score
    
    def _process_virustotal_result(self, result):
        """Process VirusTotal result and return score string."""
        logger.debug(f"Processing VirusTotal result: {json.dumps(result, indent=2)}")
        if 'error' in result:
            logger.warning(f"VirusTotal error: {result['error']}")
            return "Error: Check API key"
        
        data = result.get('data', {})
        if not data:
            logger.warning("No VirusTotal data available")
            return "No data available"
        
        try:
            # Ensure all values are integers
            malicious = int(data.get('malicious', 0))
            suspicious = int(data.get('suspicious', 0))
            harmless = int(data.get('harmless', 0))
            undetected = int(data.get('undetected', 0))
            
            total_scanners = malicious + suspicious + harmless + undetected
            
            logger.debug(f"VirusTotal stats - malicious: {malicious}, suspicious: {suspicious}, harmless: {harmless}, undetected: {undetected}, total: {total_scanners}")
            
            if total_scanners > 0:
                threat_score = round((malicious + suspicious) / total_scanners * 100)
                score = f"{threat_score}% ({malicious}/{total_scanners})"
                logger.debug(f"VirusTotal score: {score}")
                return score
            
            logger.warning("No VirusTotal scan results (total_scanners = 0)")
            return "No scan results"
        except Exception as e:
            logger.error(f"Error processing VirusTotal result: {str(e)}", exc_info=True)
            return "Error processing data"
    
    def _process_alienvault_result(self, result):
        """Process AlienVault OTX result and return score string."""
        logger.debug(f"Processing AlienVault result: {json.dumps(result, indent=2)}")
        if 'error' in result:
            logger.warning(f"AlienVault error: {result['error']}")
            return "Error: Check API key"
        
        data = result.get('data', {})
        if not data:
            logger.warning("No AlienVault data available")
            return "No data available"
        
        try:
            # Get pulse count and threat score
            pulse_count = int(data.get('pulse_count', 0))
            threat_score = int(data.get('threat_score', 0))
            
            # Get additional counts
            malware_samples = int(data.get('malware_samples', 0))
            url_count = int(data.get('url_count', 0))
            dns_count = int(data.get('dns_count', 0))
            http_scan_count = int(data.get('http_scan_count', 0))
            
            # Sum total findings for a more comprehensive view
            total_findings = pulse_count + malware_samples + url_count + dns_count
            
            logger.debug(f"AlienVault stats - pulse_count: {pulse_count}, threat_score: {threat_score}, " +
                         f"malware: {malware_samples}, urls: {url_count}, dns: {dns_count}, http_scans: {http_scan_count}")
            
            # Generate score display with more comprehensive info
            if total_findings > 0:
                # Include the breakdown of findings if there are any
                details = []
                if pulse_count > 0:
                    details.append(f"{pulse_count} reports")
                if malware_samples > 0:
                    details.append(f"{malware_samples} malware")
                if url_count > 0:
                    details.append(f"{url_count} URLs")
                if dns_count > 0:
                    details.append(f"{dns_count} DNS")
                
                # Create a score with detailed breakdown
                detailed_info = ", ".join(details)
                score = f"{threat_score}% ({detailed_info})"
                logger.debug(f"AlienVault score: {score}")
                return score
            
            logger.warning("No AlienVault threat intelligence findings")
            return "No findings"
        except Exception as e:
            logger.error(f"Error processing AlienVault result: {str(e)}", exc_info=True)
            return "Error processing data"

    def _get_location_info(self, abuseipdb_result, virustotal_result, alienvault_result=None):
        """Extract country and ISP information from results."""
        logger.debug("Getting location info")
        
        # First try to get data from AbuseIPDB (preferred source)
        if 'error' not in abuseipdb_result and abuseipdb_result.get('data'):
            country = abuseipdb_result['data'].get('countryCode', 'N/A')
            isp = abuseipdb_result['data'].get('isp', 'Unknown')
            logger.debug(f"Using AbuseIPDB location data: country={country}, isp={isp}")
            return (country, isp)
        
        # If AbuseIPDB data is not available, try VirusTotal
        elif 'error' not in virustotal_result and virustotal_result.get('data'):
            vt_data = virustotal_result.get('data', {})
            country = vt_data.get('country', 'N/A')
            isp = vt_data.get('as_owner', 'Unknown')
            logger.debug(f"Using VirusTotal location data: country={country}, isp={isp}")
            return (country, isp)
        
        # If neither is available, try AlienVault
        elif alienvault_result and 'error' not in alienvault_result and alienvault_result.get('data'):
            av_data = alienvault_result.get('data', {})
            country = av_data.get('country_code', 'N/A')
            isp = av_data.get('isp', 'Unknown')
            logger.debug(f"Using AlienVault location data: country={country}, isp={isp}")
            return (country, isp)
        
        # If none are available, return default values
        logger.warning("No location data available from any service")
        return 'N/A', 'Unknown'

    def _is_ip_malicious(self, result):
        """Determine if an IP is malicious based on scan results."""
        if result['source'] == 'all':
            # Check AbuseIPDB
            if ('error' not in result['abuseipdb'] and 
                result['abuseipdb'].get('data', {}).get('abuseConfidenceScore', 0) > 50):
                return True
            # Check VirusTotal
            if ('error' not in result['virustotal'] and 
                  result['virustotal'].get('data', {}).get('malicious', 0) > 0):
                return True
            # Check AlienVault
            if ('error' not in result['alienvault'] and 
                  result['alienvault'].get('data', {}).get('pulse_count', 0) > 0):
                return True
        elif result['source'] == 'both':
            # Check AbuseIPDB
            if ('error' not in result['abuseipdb'] and 
                result['abuseipdb'].get('data', {}).get('abuseConfidenceScore', 0) > 50):
                return True
            # Check VirusTotal
            if ('error' not in result['virustotal'] and 
                  result['virustotal'].get('data', {}).get('malicious', 0) > 0):
                return True
        else:
            # Handle single-service results
            logger.debug(f"Processing single-service result for {result['ip']}: {result['source']}")
            if 'error' in result:
                logger.warning(f"Error in {result['source']} result for {result['ip']}: {result.get('error')}")
                return False

            if result['source'] == 'abuseipdb':
                return result.get('data', {}).get('abuseConfidenceScore', 0) > 50
            elif result['source'] == 'virustotal':
                return result.get('data', {}).get('malicious', 0) > 0
            elif result['source'] == 'alienvault':
                return result.get('data', {}).get('pulse_count', 0) > 0
        return False

    def _update_table(self):
        logger.info("Updating results table")
        # Clear existing items
        for item in self.table.get_children():
            self.table.delete(item)
            
        # Add new data
        total_ips = len(self.data)
        malicious_count = sum(1 for ip, result in self.data.items() if self._is_ip_malicious(result))
        
        # Update stats with scan results
        self.stats_label.config(
            text=f"{self.stats_label.cget('text')} | {malicious_count} potentially malicious"
        )
        
        for ip, result in self.data.items():
            logger.debug(f"Processing result for IP {ip}: {json.dumps(result, indent=2)}")
            
            if result['source'] == 'all':
                # Process results from all three services
                logger.debug(f"Processing all-service results for {ip}")
                abuseipdb_score = self._process_abuseipdb_result(result['abuseipdb'])
                virustotal_score = self._process_virustotal_result(result['virustotal'])
                alienvault_score = self._process_alienvault_result(result['alienvault'])
                country, isp = self._get_location_info(result['abuseipdb'], result['virustotal'], result['alienvault'])
                
                logger.debug(f"Table values for {ip}: abuseipdb={abuseipdb_score}, virustotal={virustotal_score}, alienvault={alienvault_score}, country={country}, isp={isp}")
                self.table.insert('', tk.END, values=(
                    ip, abuseipdb_score, virustotal_score, alienvault_score, country, isp
                ))
            elif result['source'] == 'both':
                # Process combined results from AbuseIPDB and VirusTotal
                logger.debug(f"Processing combined results for {ip}")
                abuseipdb_score = self._process_abuseipdb_result(result['abuseipdb'])
                virustotal_score = self._process_virustotal_result(result['virustotal'])
                country, isp = self._get_location_info(result['abuseipdb'], result['virustotal'])
                
                logger.debug(f"Table values for {ip}: abuseipdb={abuseipdb_score}, virustotal={virustotal_score}, country={country}, isp={isp}")
                self.table.insert('', tk.END, values=(
                    ip, abuseipdb_score, virustotal_score, "N/A", country, isp
                ))
            else:
                # Handle single-service results
                if result['source'] == 'abuseipdb':
                    details = result.get('data', {})
                    logger.debug(f"AbuseIPDB details for {ip}: {json.dumps(details, indent=2)}")
                    self.table.insert('', tk.END, values=(
                        ip,
                        f"{details.get('abuseConfidenceScore', 0)}%",
                        "N/A",
                        "N/A",
                        details.get('countryCode', 'N/A'),
                        details.get('isp', 'Unknown')
                    ))
                elif result['source'] == 'virustotal':
                    logger.debug(f"Processing VirusTotal single-service result for {ip}")
                    score_display = self._process_virustotal_result(result)
                    details = result.get('data', {})
                    
                    # Get country and ISP info from VirusTotal data
                    country = details.get('country', 'N/A')
                    isp = details.get('as_owner', 'Unknown')
                    
                    logger.debug(f"VirusTotal table values for {ip}: score={score_display}, country={country}, isp={isp}")
                    self.table.insert('', tk.END, values=(
                        ip,
                        "N/A",
                        score_display,
                        "N/A",
                        country,
                        isp
                    ))
                elif result['source'] == 'alienvault':
                    logger.debug(f"Processing AlienVault single-service result for {ip}")
                    score_display = self._process_alienvault_result(result)
                    details = result.get('data', {})
                    
                    # Get country and ISP info from AlienVault data
                    country = details.get('country_code', 'N/A')
                    isp = details.get('isp', 'Unknown')
                    
                    logger.debug(f"AlienVault table values for {ip}: score={score_display}, country={country}, isp={isp}")
                    self.table.insert('', tk.END, values=(
                        ip,
                        "N/A",
                        "N/A",
                        score_display,
                        country,
                        isp
                    ))
            
        # Update stats
        total_ips = len(self.data)
        malicious_count = sum(1 for ip, result in self.data.items() if self._is_ip_malicious(result))
        
        logger.info(f"Scan stats: {total_ips} IPs scanned, {malicious_count} potentially malicious")
        self.stats_label.config(
            text=f"Scanned {total_ips} IPs | {malicious_count} potentially malicious"
        )

    def _show_details(self):
        selected = self.table.focus()
        if not selected:
            messagebox.showinfo("Info", "Please select an IP to view details")
            return
        
        item = self.table.item(selected)
        ip = item['values'][0]
        result = self.data.get(ip, {})
        
        # Create detail window
        detail_win = tk.Toplevel(self.master)
        detail_win.title(f"Details for {ip}")
        detail_win.geometry("700x500")
        
        # Create notebook for tabs
        notebook = ttk.Notebook(detail_win)
        
        # Create frames for each tab
        if result['source'] == 'all':
            # AbuseIPDB tab
            abuseipdb_frame = ttk.Frame(notebook)
            abuseipdb_text = scrolledtext.ScrolledText(abuseipdb_frame, wrap=tk.WORD)
            abuseipdb_text.insert(tk.INSERT, json.dumps(result['abuseipdb'], indent=2))
            abuseipdb_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            notebook.add(abuseipdb_frame, text="AbuseIPDB")
            
            # VirusTotal tab
            vt_frame = ttk.Frame(notebook)
            vt_text = scrolledtext.ScrolledText(vt_frame, wrap=tk.WORD)
            vt_text.insert(tk.INSERT, json.dumps(result['virustotal'], indent=2))
            vt_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            notebook.add(vt_frame, text="VirusTotal")
            
            # AlienVault tab
            av_frame = ttk.Frame(notebook)
            av_text = scrolledtext.ScrolledText(av_frame, wrap=tk.WORD)
            av_text.insert(tk.INSERT, json.dumps(result['alienvault'], indent=2))
            av_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            notebook.add(av_frame, text="AlienVault")
            
            # Create a formatted summary tab
            summary_frame = ttk.Frame(notebook)
            summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD)
            
            # Add AbuseIPDB summary
            if 'error' not in result['abuseipdb']:
                abuseipdb_data = result['abuseipdb'].get('data', {})
                summary_text.insert(tk.INSERT, "=== AbuseIPDB Summary ===\n")
                summary_text.insert(tk.INSERT, f"Abuse Score: {abuseipdb_data.get('abuseConfidenceScore', 0)}%\n")
                summary_text.insert(tk.INSERT, f"Country: {abuseipdb_data.get('countryCode', 'N/A')}\n")
                summary_text.insert(tk.INSERT, f"ISP: {abuseipdb_data.get('isp', 'Unknown')}\n")
                summary_text.insert(tk.INSERT, f"Domain: {abuseipdb_data.get('domain', 'N/A')}\n")
                summary_text.insert(tk.INSERT, f"Usage Type: {abuseipdb_data.get('usageType', 'N/A')}\n\n")
            
            # Add VirusTotal summary
            if 'error' not in result['virustotal']:
                vt_data = result['virustotal'].get('data', {})
                summary_text.insert(tk.INSERT, "=== VirusTotal Summary ===\n")
                
                # Analysis stats
                malicious = vt_data.get('malicious', 0)
                suspicious = vt_data.get('suspicious', 0)
                harmless = vt_data.get('harmless', 0)
                undetected = vt_data.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                summary_text.insert(tk.INSERT, f"Detection Stats: {malicious} malicious, {suspicious} suspicious, {harmless} harmless, {undetected} undetected\n")
                summary_text.insert(tk.INSERT, f"Threat Score: {round((malicious + suspicious) / total * 100) if total > 0 else 0}%\n")
                summary_text.insert(tk.INSERT, f"Country: {vt_data.get('country', 'N/A')}\n")
                summary_text.insert(tk.INSERT, f"AS Owner: {vt_data.get('as_owner', 'Unknown')}\n")
                summary_text.insert(tk.INSERT, f"ASN: {vt_data.get('asn', 'N/A')}\n")
                summary_text.insert(tk.INSERT, f"Network: {vt_data.get('network', 'N/A')}\n")
                
                # Tags if available
                tags = vt_data.get('tags', [])
                if tags:
                    summary_text.insert(tk.INSERT, f"Tags: {', '.join(tags)}\n")
            
            # Add AlienVault summary
            if 'error' not in result['alienvault']:
                av_data = result['alienvault'].get('data', {})
                summary_text.insert(tk.INSERT, "=== AlienVault OTX Summary ===\n")
                
                # Report stats
                pulse_count = av_data.get('pulse_count', 0)
                threat_score = av_data.get('threat_score', 0)
                malware_samples = av_data.get('malware_samples', 0)
                url_count = av_data.get('url_count', 0)
                dns_count = av_data.get('dns_count', 0)
                http_scan_count = av_data.get('http_scan_count', 0)
                
                summary_text.insert(tk.INSERT, f"Pulse Count: {pulse_count} reports\n")
                summary_text.insert(tk.INSERT, f"Threat Score: {threat_score}%\n")
                summary_text.insert(tk.INSERT, f"Malware Samples: {malware_samples}\n")
                summary_text.insert(tk.INSERT, f"Associated URLs: {url_count}\n")
                summary_text.insert(tk.INSERT, f"DNS Records: {dns_count}\n")
                summary_text.insert(tk.INSERT, f"HTTP Scans: {http_scan_count}\n")
                summary_text.insert(tk.INSERT, f"Country: {av_data.get('country_name', 'N/A')} ({av_data.get('country_code', 'N/A')})\n")
                summary_text.insert(tk.INSERT, f"City: {av_data.get('city', 'N/A')}\n")
                summary_text.insert(tk.INSERT, f"ASN: {av_data.get('asn', 'N/A')}\n")
                
                # Tags if available
                tags = av_data.get('tags', [])
                if tags:
                    summary_text.insert(tk.INSERT, f"Tags: {', '.join(tags)}\n")
                
                # Malware families if available
                malware_families = av_data.get('malware_families', [])
                if malware_families:
                    summary_text.insert(tk.INSERT, f"Malware Families: {', '.join(malware_families)}\n")
                
                # Associated URLs if available
                associated_urls = av_data.get('associated_urls', [])
                if associated_urls:
                    summary_text.insert(tk.INSERT, "\nAssociated URLs:\n")
                    for url in associated_urls:
                        summary_text.insert(tk.INSERT, f"- {url}\n")
                
                # DNS records if available
                dns_records = av_data.get('dns_records', [])
                if dns_records:
                    summary_text.insert(tk.INSERT, "\nDNS Records:\n")
                    for record in dns_records:
                        summary_text.insert(tk.INSERT, f"- {record['hostname']} ({record['record_type']})\n")
                        summary_text.insert(tk.INSERT, f"  First seen: {record['first_seen']}, Last seen: {record['last_seen']}\n")
                
                # HTTP scans if available
                http_scans = av_data.get('http_scans', [])
                if http_scans:
                    summary_text.insert(tk.INSERT, "\nHTTP Scans:\n")
                    for scan in http_scans:
                        summary_text.insert(tk.INSERT, f"- {scan['date']} | {scan['method']} | {scan['url_port']} | Status: {scan['http_status']}\n")
                        if scan['server'] != 'N/A':
                            summary_text.insert(tk.INSERT, f"  Server: {scan['server']}, Content Type: {scan['content_type']}\n")
            
            summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            notebook.add(summary_frame, text="Summary")
            
            # Combined tab
            combined_frame = ttk.Frame(notebook)
            combined_text = scrolledtext.ScrolledText(combined_frame, wrap=tk.WORD)
            combined_text.insert(tk.INSERT, json.dumps(result, indent=2))
            combined_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            notebook.add(combined_frame, text="Raw Data")
        elif result['source'] == 'both':
            # AbuseIPDB tab
            abuseipdb_frame = ttk.Frame(notebook)
            abuseipdb_text = scrolledtext.ScrolledText(abuseipdb_frame, wrap=tk.WORD)
            abuseipdb_text.insert(tk.INSERT, json.dumps(result['abuseipdb'], indent=2))
            abuseipdb_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            notebook.add(abuseipdb_frame, text="AbuseIPDB")
            
            # VirusTotal tab
            vt_frame = ttk.Frame(notebook)
            vt_text = scrolledtext.ScrolledText(vt_frame, wrap=tk.WORD)
            vt_text.insert(tk.INSERT, json.dumps(result['virustotal'], indent=2))
            vt_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            notebook.add(vt_frame, text="VirusTotal")
            
            # Create a formatted summary tab
            summary_frame = ttk.Frame(notebook)
            summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD)
            
            # Add AbuseIPDB summary
            if 'error' not in result['abuseipdb']:
                abuseipdb_data = result['abuseipdb'].get('data', {})
                summary_text.insert(tk.INSERT, "=== AbuseIPDB Summary ===\n")
                summary_text.insert(tk.INSERT, f"Abuse Score: {abuseipdb_data.get('abuseConfidenceScore', 0)}%\n")
                summary_text.insert(tk.INSERT, f"Country: {abuseipdb_data.get('countryCode', 'N/A')}\n")
                summary_text.insert(tk.INSERT, f"ISP: {abuseipdb_data.get('isp', 'Unknown')}\n")
                summary_text.insert(tk.INSERT, f"Domain: {abuseipdb_data.get('domain', 'N/A')}\n")
                summary_text.insert(tk.INSERT, f"Usage Type: {abuseipdb_data.get('usageType', 'N/A')}\n\n")
            
            # Add VirusTotal summary
            if 'error' not in result['virustotal']:
                vt_data = result['virustotal'].get('data', {})
                summary_text.insert(tk.INSERT, "=== VirusTotal Summary ===\n")
                
                # Analysis stats
                malicious = vt_data.get('malicious', 0)
                suspicious = vt_data.get('suspicious', 0)
                harmless = vt_data.get('harmless', 0)
                undetected = vt_data.get('undetected', 0)
                total = malicious + suspicious + harmless + undetected
                
                summary_text.insert(tk.INSERT, f"Detection Stats: {malicious} malicious, {suspicious} suspicious, {harmless} harmless, {undetected} undetected\n")
                summary_text.insert(tk.INSERT, f"Threat Score: {round((malicious + suspicious) / total * 100) if total > 0 else 0}%\n")
                summary_text.insert(tk.INSERT, f"Country: {vt_data.get('country', 'N/A')}\n")
                summary_text.insert(tk.INSERT, f"AS Owner: {vt_data.get('as_owner', 'Unknown')}\n")
                summary_text.insert(tk.INSERT, f"ASN: {vt_data.get('asn', 'N/A')}\n")
                summary_text.insert(tk.INSERT, f"Network: {vt_data.get('network', 'N/A')}\n")
                
                # Tags if available
                tags = vt_data.get('tags', [])
                if tags:
                    summary_text.insert(tk.INSERT, f"Tags: {', '.join(tags)}\n")
            
            summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            notebook.add(summary_frame, text="Summary")
            
            # Combined tab
            combined_frame = ttk.Frame(notebook)
            combined_text = scrolledtext.ScrolledText(combined_frame, wrap=tk.WORD)
            combined_text.insert(tk.INSERT, json.dumps(result, indent=2))
            combined_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            notebook.add(combined_frame, text="Raw Data")
        else:
            # Single service tab
            single_frame = ttk.Frame(notebook)
            single_text = scrolledtext.ScrolledText(single_frame, wrap=tk.WORD)
            single_text.insert(tk.INSERT, json.dumps(result, indent=2))
            single_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            notebook.add(single_frame, text=result['source'].capitalize())
            
            # Add a formatted summary tab for single service
            if 'error' not in result:
                summary_frame = ttk.Frame(notebook)
                summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD)
                
                if result['source'] == 'abuseipdb':
                    abuseipdb_data = result.get('data', {})
                    summary_text.insert(tk.INSERT, "=== AbuseIPDB Summary ===\n")
                    summary_text.insert(tk.INSERT, f"Abuse Score: {abuseipdb_data.get('abuseConfidenceScore', 0)}%\n")
                    summary_text.insert(tk.INSERT, f"Country: {abuseipdb_data.get('countryCode', 'N/A')}\n")
                    summary_text.insert(tk.INSERT, f"ISP: {abuseipdb_data.get('isp', 'Unknown')}\n")
                    summary_text.insert(tk.INSERT, f"Domain: {abuseipdb_data.get('domain', 'N/A')}\n")
                    summary_text.insert(tk.INSERT, f"Usage Type: {abuseipdb_data.get('usageType', 'N/A')}\n")
                elif result['source'] == 'virustotal':
                    vt_data = result.get('data', {})
                    summary_text.insert(tk.INSERT, "=== VirusTotal Summary ===\n")
                    
                    # Analysis stats
                    malicious = vt_data.get('malicious', 0)
                    suspicious = vt_data.get('suspicious', 0)
                    harmless = vt_data.get('harmless', 0)
                    undetected = vt_data.get('undetected', 0)
                    total = malicious + suspicious + harmless + undetected
                    
                    summary_text.insert(tk.INSERT, f"Detection Stats: {malicious} malicious, {suspicious} suspicious, {harmless} harmless, {undetected} undetected\n")
                    summary_text.insert(tk.INSERT, f"Threat Score: {round((malicious + suspicious) / total * 100) if total > 0 else 0}%\n")
                    summary_text.insert(tk.INSERT, f"Country: {vt_data.get('country', 'N/A')}\n")
                    summary_text.insert(tk.INSERT, f"AS Owner: {vt_data.get('as_owner', 'Unknown')}\n")
                    summary_text.insert(tk.INSERT, f"ASN: {vt_data.get('asn', 'N/A')}\n")
                    summary_text.insert(tk.INSERT, f"Network: {vt_data.get('network', 'N/A')}\n")
                    
                    # Tags if available
                    tags = vt_data.get('tags', [])
                    if tags:
                        summary_text.insert(tk.INSERT, f"Tags: {', '.join(tags)}\n")
                elif result['source'] == 'alienvault':
                    av_data = result.get('data', {})
                    summary_text.insert(tk.INSERT, "=== AlienVault OTX Summary ===\n")
                    
                    # Report stats
                    pulse_count = av_data.get('pulse_count', 0)
                    threat_score = av_data.get('threat_score', 0)
                    malware_samples = av_data.get('malware_samples', 0)
                    url_count = av_data.get('url_count', 0)
                    dns_count = av_data.get('dns_count', 0)
                    http_scan_count = av_data.get('http_scan_count', 0)
                    
                    summary_text.insert(tk.INSERT, f"Pulse Count: {pulse_count} reports\n")
                    summary_text.insert(tk.INSERT, f"Threat Score: {threat_score}%\n")
                    summary_text.insert(tk.INSERT, f"Malware Samples: {malware_samples}\n")
                    summary_text.insert(tk.INSERT, f"Associated URLs: {url_count}\n")
                    summary_text.insert(tk.INSERT, f"DNS Records: {dns_count}\n")
                    summary_text.insert(tk.INSERT, f"HTTP Scans: {http_scan_count}\n")
                    summary_text.insert(tk.INSERT, f"Country: {av_data.get('country_name', 'N/A')} ({av_data.get('country_code', 'N/A')})\n")
                    summary_text.insert(tk.INSERT, f"City: {av_data.get('city', 'N/A')}\n")
                    summary_text.insert(tk.INSERT, f"ASN: {av_data.get('asn', 'N/A')}\n")
                    
                    # Tags if available
                    tags = av_data.get('tags', [])
                    if tags:
                        summary_text.insert(tk.INSERT, f"Tags: {', '.join(tags)}\n")
                    
                    # Malware families if available
                    malware_families = av_data.get('malware_families', [])
                    if malware_families:
                        summary_text.insert(tk.INSERT, f"Malware Families: {', '.join(malware_families)}\n")
                    
                    # Associated URLs if available
                    associated_urls = av_data.get('associated_urls', [])
                    if associated_urls:
                        summary_text.insert(tk.INSERT, "\nAssociated URLs:\n")
                        for url in associated_urls:
                            summary_text.insert(tk.INSERT, f"- {url}\n")
                    
                    # DNS records if available
                    dns_records = av_data.get('dns_records', [])
                    if dns_records:
                        summary_text.insert(tk.INSERT, "\nDNS Records:\n")
                        for record in dns_records:
                            summary_text.insert(tk.INSERT, f"- {record['hostname']} ({record['record_type']})\n")
                            summary_text.insert(tk.INSERT, f"  First seen: {record['first_seen']}, Last seen: {record['last_seen']}\n")
                    
                    # HTTP scans if available
                    http_scans = av_data.get('http_scans', [])
                    if http_scans:
                        summary_text.insert(tk.INSERT, "\nHTTP Scans:\n")
                        for scan in http_scans:
                            summary_text.insert(tk.INSERT, f"- {scan['date']} | {scan['method']} | {scan['url_port']} | Status: {scan['http_status']}\n")
                            if scan['server'] != 'N/A':
                                summary_text.insert(tk.INSERT, f"  Server: {scan['server']}, Content Type: {scan['content_type']}\n")
                
                summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                notebook.add(summary_frame, text="Summary")
        
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _open_virustotal(self):
        """Open selected IP in VirusTotal"""
        selection = self.table.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an IP address first")
            return
            
        ip = self.table.item(selection[0])['values'][0]
        url = f"https://www.virustotal.com/gui/ip-address/{ip}"
        webbrowser.open(url)

    def _open_abuseipdb(self):
        """Open selected IP in AbuseIPDB"""
        selection = self.table.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an IP address first")
            return
            
        ip = self.table.item(selection[0])['values'][0]
        url = f"https://www.abuseipdb.com/check/{ip}"
        webbrowser.open(url)

    def _open_alienvault(self):
        """Open selected IP in AlienVault OTX"""
        selection = self.table.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an IP address first")
            return
            
        ip = self.table.item(selection[0])['values'][0]
        url = f"https://otx.alienvault.com/indicator/ip/{ip}"
        webbrowser.open(url)

    def _export_results(self):
        """Export scan results to JSON file"""
        if not self.data:
            messagebox.showwarning("Warning", "No scan results to export")
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.data, f, indent=2)
            messagebox.showinfo("Success", f"Results exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")

    def _show_ai_analysis(self):
        """Show AI analysis window"""
        if not self.data:
            messagebox.showwarning("Warning", "No scan results to analyze")
            return
            
        # Create new window for analysis
        if self.analysis_window is None or not tk.Toplevel.winfo_exists(self.analysis_window):
            self.analysis_window = tk.Toplevel(self.master)
            self.analysis_window.title("AI Analysis")
            self.analysis_window.geometry("600x400")
            
            # Analysis text area
            self.analysis_text = scrolledtext.ScrolledText(
                self.analysis_window,
                wrap=tk.WORD,
                width=60,
                height=20
            )
            self.analysis_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
            
            # Clarification frame
            clarification_frame = ttk.Frame(self.analysis_window)
            self.clarification_entry = ttk.Entry(clarification_frame, width=40)
            self.clarification_entry.pack(side=tk.LEFT, padx=5)
            
            ttk.Button(
                clarification_frame,
                text="Ask for Clarification",
                command=self._get_clarification
            ).pack(side=tk.LEFT, padx=5)
            
            clarification_frame.pack(pady=5)
            
            # Perform initial analysis
            self._perform_analysis()

    def _perform_analysis(self):
        """Perform AI analysis of results"""
        try:
            result = analyze_results(self.data)
            
            if 'error' in result:
                self.analysis_text.insert(tk.END, f"Error: {result['error']}\n")
                return
                
            self.analysis_text.delete(1.0, tk.END)
            self.analysis_text.insert(tk.END, result['analysis'])
            
            if result['needs_clarification']:
                self.analysis_text.insert(tk.END, "\n\nPlease provide additional information if needed.")
                
        except Exception as e:
            self.analysis_text.insert(tk.END, f"Analysis error: {str(e)}\n")

    def _get_clarification(self):
        """Get clarification from AI about specific aspects"""
        additional_info = self.clarification_entry.get()
        if not additional_info:
            messagebox.showwarning("Warning", "Please enter your question or additional information")
            return
            
        try:
            clarification = get_clarification(
                self.analysis_text.get(1.0, tk.END),
                additional_info
            )
            
            self.analysis_text.insert(tk.END, "\n\n--- Clarification ---\n")
            self.analysis_text.insert(tk.END, f"Question: {additional_info}\n")
            self.analysis_text.insert(tk.END, f"Response: {clarification}\n")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get clarification: {str(e)}")

    def _debug_data(self):
        """Show debug information for the current data"""
        if not self.data:
            messagebox.showinfo("Debug", "No data available to debug")
            return
            
        # Create debug window
        debug_win = tk.Toplevel(self.master)
        debug_win.title("Debug Data")
        debug_win.geometry("800x600")
        
        # Create notebook for tabs
        notebook = ttk.Notebook(debug_win)
        
        # Create a tab for raw data
        raw_frame = ttk.Frame(notebook)
        raw_text = scrolledtext.ScrolledText(raw_frame, wrap=tk.WORD)
        raw_text.insert(tk.INSERT, json.dumps(self.data, indent=2))
        raw_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook.add(raw_frame, text="Raw Data")
        
        # Create a tab for VirusTotal data
        vt_frame = ttk.Frame(notebook)
        vt_text = scrolledtext.ScrolledText(vt_frame, wrap=tk.WORD)
        
        # Extract and format VirusTotal data
        vt_data = {}
        for ip, result in self.data.items():
            if result['source'] == 'both':
                vt_data[ip] = result['virustotal']
            elif result['source'] == 'virustotal':
                vt_data[ip] = result
        
        vt_text.insert(tk.INSERT, json.dumps(vt_data, indent=2))
        vt_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook.add(vt_frame, text="VirusTotal Data")
        
        # Create a tab for processed data
        processed_frame = ttk.Frame(notebook)
        processed_text = scrolledtext.ScrolledText(processed_frame, wrap=tk.WORD)
        
        # Process and display data as it would appear in the table
        processed_data = {}
        for ip, result in self.data.items():
            entry = {}
            
            if result['source'] == 'all':
                entry['abuseipdb_score'] = self._process_abuseipdb_result(result['abuseipdb'])
                entry['virustotal_score'] = self._process_virustotal_result(result['virustotal'])
                entry['alienvault_score'] = self._process_alienvault_result(result['alienvault'])
                country, isp = self._get_location_info(result['abuseipdb'], result['virustotal'], result['alienvault'])
                entry['country'] = country
                entry['isp'] = isp
                
                # Add raw data for reference
                entry['abuseipdb_raw'] = result['abuseipdb'].get('data', {})
                entry['virustotal_raw'] = result['virustotal'].get('data', {})
            elif result['source'] == 'both':
                entry['abuseipdb_score'] = self._process_abuseipdb_result(result['abuseipdb'])
                entry['virustotal_score'] = self._process_virustotal_result(result['virustotal'])
                country, isp = self._get_location_info(result['abuseipdb'], result['virustotal'])
                entry['country'] = country
                entry['isp'] = isp
                
                # Add raw data for reference
                entry['abuseipdb_raw'] = result['abuseipdb'].get('data', {})
                entry['virustotal_raw'] = result['virustotal'].get('data', {})
            else:
                if result['source'] == 'abuseipdb':
                    entry['abuseipdb_score'] = self._process_abuseipdb_result(result)
                    entry['virustotal_score'] = "N/A"
                    entry['alienvault_score'] = "N/A"
                    entry['country'] = result.get('data', {}).get('countryCode', 'N/A')
                    entry['isp'] = result.get('data', {}).get('isp', 'Unknown')
                    entry['abuseipdb_raw'] = result.get('data', {})
                elif result['source'] == 'virustotal':
                    entry['abuseipdb_score'] = "N/A"
                    entry['virustotal_score'] = self._process_virustotal_result(result)
                    entry['alienvault_score'] = "N/A"
                    entry['country'] = result.get('data', {}).get('country', 'N/A')
                    entry['isp'] = result.get('data', {}).get('as_owner', 'Unknown')
                    entry['virustotal_raw'] = result.get('data', {})
                elif result['source'] == 'alienvault':
                    entry['abuseipdb_score'] = "N/A"
                    entry['virustotal_score'] = "N/A"
                    entry['alienvault_score'] = self._process_alienvault_result(result)
                    entry['country'] = result.get('data', {}).get('country_code', 'N/A')
                    entry['isp'] = result.get('data', {}).get('isp', 'Unknown')
                    entry['alienvault_raw'] = result.get('data', {})
            
            processed_data[ip] = entry
        
        processed_text.insert(tk.INSERT, json.dumps(processed_data, indent=2))
        processed_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook.add(processed_frame, text="Processed Data")
        
        # Create a tab for environment info
        env_frame = ttk.Frame(notebook)
        env_text = scrolledtext.ScrolledText(env_frame, wrap=tk.WORD)
        
        # Get environment info
        import platform
        import sys
        
        env_info = {
            "platform": platform.platform(),
            "python_version": sys.version,
            "tkinter_version": tk.TkVersion,
            "services_used": "Using all services (AbuseIPDB, VirusTotal, AlienVault)",
            "ip_count": len(self.ip_list),
            "result_count": len(self.data)
        }
        
        env_text.insert(tk.INSERT, json.dumps(env_info, indent=2))
        env_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        notebook.add(env_frame, text="Environment")
        
        # Create a tab for direct API test
        api_test_frame = ttk.Frame(notebook)
        
        # Create input area
        input_frame = ttk.Frame(api_test_frame)
        ttk.Label(input_frame, text="IP Address:").pack(side=tk.LEFT, padx=5)
        ip_entry = ttk.Entry(input_frame, width=20)
        ip_entry.pack(side=tk.LEFT, padx=5)
        
        # Use fixed service value
        service_var = tk.StringVar(value="all")
        ttk.Label(
            input_frame, 
            text="Using all services (AbuseIPDB, VirusTotal, AlienVault)",
            font=('Helvetica', 9, 'italic')
        ).pack(side=tk.LEFT, padx=5)
        
        input_frame.pack(pady=10)
        
        # Create output area
        output_text = scrolledtext.ScrolledText(api_test_frame, wrap=tk.WORD, height=20)
        output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Test button
        def run_api_test():
            ip = ip_entry.get().strip()
            if not ip:
                output_text.insert(tk.INSERT, "Please enter an IP address\n")
                return
                
            service = service_var.get()
            output_text.delete(1.0, tk.END)
            output_text.insert(tk.INSERT, f"Testing all services for IP: {ip}\n\n")
            
            try:
                
                result = check_ip_abuse(ip, service="all")
                output_text.insert(tk.INSERT, json.dumps(result, indent=2))
                
                # Display summary of results
                output_text.insert(tk.END, "\n\nResults Summary:\n")
                if 'abuseipdb' in result:
                    abuseipdb_score = self._process_abuseipdb_result(result['abuseipdb'])
                    output_text.insert(tk.END, f"AbuseIPDB Score: {abuseipdb_score}\n")
                if 'virustotal' in result:
                    virustotal_score = self._process_virustotal_result(result['virustotal'])
                    output_text.insert(tk.END, f"VirusTotal Score: {virustotal_score}\n")
                if 'alienvault' in result:
                    alienvault_score = self._process_alienvault_result(result['alienvault'])
                    output_text.insert(tk.END, f"AlienVault Score: {alienvault_score}\n")
                
            except Exception as e:
                output_text.insert(tk.INSERT, f"Error: {str(e)}\n")
                import traceback
                output_text.insert(tk.INSERT, traceback.format_exc())
        
        ttk.Button(
            api_test_frame,
            text="Test API",
            command=run_api_test
        ).pack(pady=5)
        
        notebook.add(api_test_frame, text="API Test")
        
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10) 