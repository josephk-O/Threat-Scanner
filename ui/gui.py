import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from ttkthemes import ThemedTk
import json
import webbrowser
from datetime import datetime
from scanner.threat_intel import check_ip_abuse
from scanner.ai_analysis import analyze_results, get_clarification
from handlers.threat_logging import ThreatScanLogger

logger = ThreatScanLogger("gui", logger_level='INFO')

class ThreatScannerUI:
    def __init__(self, master, scanner_callback=None):
        self.master = master
        self.scanner_callback = scanner_callback
        self.data = {}
        self.current_service = tk.StringVar(value='all')  # Default to all services
        self.ip_list = []
        self.analysis_window = None
        self._pending_action_reflow = None
        
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
        panel.pack(fill=tk.X, pady=10)

        self._action_panel = panel
        self._action_buttons_frame = ttk.Frame(panel)
        self._action_buttons_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self._overflow_menu = ttk.Menubutton(panel, text="More…")
        self._overflow_menu_menu = tk.Menu(self._overflow_menu, tearoff=False)
        self._overflow_menu["menu"] = self._overflow_menu_menu
        self._overflow_menu.state(["disabled"])
        # Do not pack overflow menu yet; we only show it when needed.

        actions = [
            ("Export Results", self._export_results),
            ("View Details", self._show_details),
            ("Open in AbuseIPDB", self._open_abuseipdb),
            ("Open in VirusTotal", self._open_virustotal),
            ("Open in AlienVault", self._open_alienvault),
            ("AI security report", self._show_ai_analysis),
            ("Debug Data", self._debug_data),
        ]

        self._action_items = []
        for label, command in actions:
            button = ttk.Button(self._action_buttons_frame, text=label, command=command)
            self._action_items.append({
                "label": label,
                "command": command,
                "button": button,
            })

        panel.bind("<Configure>", lambda event: self._schedule_action_reflow())
        self._schedule_action_reflow()

    def _schedule_action_reflow(self):
        if self._pending_action_reflow is not None:
            self.master.after_cancel(self._pending_action_reflow)
        self._pending_action_reflow = self.master.after(75, self._reflow_action_buttons)

    def _reflow_action_buttons(self):
        self._pending_action_reflow = None

        if not hasattr(self, "_action_items") or not self._action_items:
            return

        panel_width = self._action_panel.winfo_width()
        if panel_width <= 1:
            self._schedule_action_reflow()
            return

        def required_width(item):
            button = item["button"]
            button.update_idletasks()
            return button.winfo_reqwidth() + 10

        # First try to fit all buttons without an overflow menu.
        total_required = sum(required_width(item) for item in self._action_items)
        overflow_items = []
        visible_items = list(self._action_items)

        if total_required > panel_width:
            # Reserve space for the overflow menu and determine visible buttons.
            menu_width = self._overflow_menu.winfo_reqwidth() + 16
            available = max(panel_width - menu_width, 0)
            current_width = 0
            visible_items = []
            overflow_items = []
            for item in self._action_items:
                width = required_width(item)
                if current_width + width <= available or not visible_items:
                    visible_items.append(item)
                    current_width += width
                else:
                    overflow_items.append(item)

        # Clear existing layout.
        for item in self._action_items:
            item["button"].pack_forget()

        self._overflow_menu_menu.delete(0, tk.END)

        for item in visible_items:
            item["button"].pack(side=tk.LEFT, padx=5)

        if overflow_items:
            if not self._overflow_menu.winfo_ismapped():
                self._overflow_menu.pack(side=tk.RIGHT, padx=5)
            for item in overflow_items:
                self._overflow_menu_menu.add_command(
                    label=item["label"],
                    command=item["command"],
                )
            self._overflow_menu.state(["!disabled"])
        else:
            if self._overflow_menu.winfo_ismapped():
                self._overflow_menu.pack_forget()
            self._overflow_menu.state(["disabled"])

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
            logger.info(f"Starting GUI scan with service: {service}")
            
            # Update stats label to show scanning status
            self.stats_label.config(text="Scanning...")
            
            # Create progress window
            progress_win = tk.Toplevel(self.master)
            progress_win.title("Scanning...")
            progress_win.geometry("300x150")
            progress_win.transient(self.master)  # Make window modal
            
            # Add progress label
            progress_label = ttk.Label(progress_win, text="Scanning IP addresses...")
            progress_label.pack(pady=10)
            
            # Add progress bar
            progress_var = tk.DoubleVar(progress_win)
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
            
            # Thread-safe update function
            def safe_update(progress, status_text):
                if not progress_win.winfo_exists():
                    return
                try:
                    self.master.after_idle(lambda: [
                        progress_var.set(progress),
                        status_label.config(text=status_text),
                        progress_win.update()
                    ])
                except Exception as e:
                    logger.error(f"Error updating progress: {str(e)}")
            
            # Run scan in a separate thread to prevent GUI freezing
            def run_scan():
                try:
                    logger.info("Starting scan thread")
                    requested_ips = list(self.ip_list) if self.ip_list else None
                    provided_ips = bool(requested_ips)

                    def progress_callback(ip, completed, total):
                        total = total or completed or 1
                        progress = (completed / total) * 100
                        status_text = f"Scanning {ip}... ({completed}/{total})"
                        logger.debug(status_text)
                        safe_update(progress, status_text)

                    target_info = (
                        f"{len(requested_ips)} provided IPs"
                        if requested_ips
                        else "collected IPs"
                    )
                    logger.info(f"Scanning {target_info} with {service} service")

                    scan_data = self.scanner_callback(
                        requested_ips,
                        service=service,
                        max_workers=10,
                        progress_callback=progress_callback
                    )

                    self.data = scan_data.get('results', {})
                    collection_stats = scan_data.get('collection_stats', {})
                    scan_stats = scan_data.get('scan_stats', {})
                    scanned_ips = scan_data.get('ip_list', [])
                    self.ip_list = list(scanned_ips)

                    def update_ui():
                        if progress_win.winfo_exists():
                            progress_win.destroy()

                        if not provided_ips:
                            total_collected = len(scanned_ips)
                            self.ip_status.config(
                                text=f"Collected {total_collected} IPs for scan"
                                if total_collected
                                else "No IP list loaded"
                            )
                        else:
                            self.ip_status.config(
                                text=f"Loaded {len(self.ip_list)} IPs for scan"
                            )

                        summary_text = (
                            f"Scanned {scan_stats.get('total_ips', len(scanned_ips))} IPs | "
                            f"{scan_stats.get('active_ips', 0)} succeeded | "
                            f"{scan_stats.get('failed_ips', 0)} failed | "
                            f"Threat detections: {scan_stats.get('threats_found', 0)}"
                        )

                        if collection_stats.get('message'):
                            logger.info(collection_stats['message'])

                        self.stats_label.config(text=summary_text)
                        self._update_table()

                    self.master.after_idle(update_ui)
                    logger.info("Scan completed successfully")

                except Exception as e:
                    logger.error(f"Error during scan: {str(e)}", exc_info=True)
                    def show_error():
                        if progress_win.winfo_exists():
                            progress_win.destroy()
                        messagebox.showerror("Error", str(e))
                        self.stats_label.config(text="Scan failed")
                    self.master.after_idle(show_error)
            
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
        try:
            # Handle case where result is None or not a dict
            if not result or not isinstance(result, dict):
                logger.warning(f"Invalid result format: {result}")
                return False

            # Handle error cases
            if 'error' in result:
                logger.warning(f"Error in result: {result['error']}")
                return False

            # Get the source from result
            source = result.get('source', '')
            
            if source == 'all':
                # Check AbuseIPDB
                abuseipdb = result.get('abuseipdb', {})
                if ('error' not in abuseipdb and 
                    abuseipdb.get('data', {}).get('abuseConfidenceScore', 0) > 50):
                    return True
                    
                # Check VirusTotal
                virustotal = result.get('virustotal', {})
                if ('error' not in virustotal and 
                    virustotal.get('data', {}).get('malicious', 0) > 0):
                    return True
                    
                # Check AlienVault
                alienvault = result.get('alienvault', {})
                if ('error' not in alienvault and 
                    alienvault.get('data', {}).get('pulse_count', 0) > 0):
                    return True
                    
            elif source == 'both':
                # Check AbuseIPDB
                abuseipdb = result.get('abuseipdb', {})
                if ('error' not in abuseipdb and 
                    abuseipdb.get('data', {}).get('abuseConfidenceScore', 0) > 50):
                    return True
                    
                # Check VirusTotal
                virustotal = result.get('virustotal', {})
                if ('error' not in virustotal and 
                    virustotal.get('data', {}).get('malicious', 0) > 0):
                    return True
                    
            elif source == 'abuseipdb':
                return ('error' not in result and 
                       result.get('data', {}).get('abuseConfidenceScore', 0) > 50)
                       
            elif source == 'virustotal':
                return ('error' not in result and 
                       result.get('data', {}).get('malicious', 0) > 0)
                       
            elif source == 'alienvault':
                return ('error' not in result and 
                       result.get('data', {}).get('pulse_count', 0) > 0)
                       
            return False
            
        except Exception as e:
            logger.error(f"Error checking if IP is malicious: {str(e)}", exc_info=True)
            return False

    def _update_table(self):
        """Update the results table with scan data."""
        logger.info("Updating results table")
        try:
            # Clear existing items
            for item in self.table.get_children():
                self.table.delete(item)
            
            if not self.data:
                logger.warning("No data to update table")
                return
            
            # Add new data
            malicious_count = 0
            total_ips = 0
            
            for ip, result in self.data.items():
                try:
                    # logger.debug(f"Processing result for IP {ip}: {json.dumps(result, indent=2)}")
                    total_ips += 1
                    
                    if self._is_ip_malicious(result):
                        malicious_count += 1
                    
                    if result.get('source') == 'all':
                        # Process results from all three services
                        # logger.debug(f"Processing all-service results for {ip}")
                        abuseipdb_score = self._process_abuseipdb_result(result.get('abuseipdb', {}))
                        virustotal_score = self._process_virustotal_result(result.get('virustotal', {}))
                        alienvault_score = self._process_alienvault_result(result.get('alienvault', {}))
                        country, isp = self._get_location_info(
                            result.get('abuseipdb', {}),
                            result.get('virustotal', {}),
                            result.get('alienvault', {})
                        )
                        
                        # logger.debug(f"Table values for {ip}: abuseipdb={abuseipdb_score}, "
                        #            f"virustotal={virustotal_score}, alienvault={alienvault_score}, "
                        #            f"country={country}, isp={isp}")
                        
                        self.table.insert('', tk.END, values=(
                            ip, abuseipdb_score, virustotal_score, alienvault_score, country, isp
                        ))
                    else:
                        # Handle single service results
                        self._insert_single_service_result(ip, result)
                    
                except Exception as e:
                    # logger.error(f"Error processing result for IP {ip}: {str(e)}", exc_info=True)
                    # Add error row to table
                    self.table.insert('', tk.END, values=(
                        ip, "Error", "Error", "Error", "N/A", f"Error: {str(e)}"
                    ))
            
            # Update stats
            stats_text = f"Scanned {total_ips} IPs | {malicious_count} potentially malicious"
            logger.info(stats_text)
            self.stats_label.config(text=stats_text)
            
        except Exception as e:
            logger.error(f"Error updating table: {str(e)}", exc_info=True)
            messagebox.showerror("Error", f"Failed to update results table: {str(e)}")

    def _insert_single_service_result(self, ip, result):
        """Insert a single service result into the table."""
        source = result.get('source', '')
        if source == 'abuseipdb':
            score = self._process_abuseipdb_result(result)
            data = result.get('data', {})
            self.table.insert('', tk.END, values=(
                ip, score, "N/A", "N/A",
                data.get('countryCode', 'N/A'),
                data.get('isp', 'Unknown')
            ))
        elif source == 'virustotal':
            score = self._process_virustotal_result(result)
            data = result.get('data', {})
            self.table.insert('', tk.END, values=(
                ip, "N/A", score, "N/A",
                data.get('country', 'N/A'),
                data.get('as_owner', 'Unknown')
            ))
        elif source == 'alienvault':
            score = self._process_alienvault_result(result)
            data = result.get('data', {})
            self.table.insert('', tk.END, values=(
                ip, "N/A", "N/A", score,
                data.get('country_code', 'N/A'),
                data.get('isp', 'Unknown')
            ))
        else:
            logger.warning(f"Unknown service source: {source}")
            self.table.insert('', tk.END, values=(
                ip, "N/A", "N/A", "N/A", "N/A", "Unknown service"
            ))

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
                country, isp = self._get_location_info(
                    result.get('abuseipdb', {}),
                    result.get('virustotal', {}),
                    result.get('alienvault', {})
                )
                
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
