import platform
import re
import subprocess
from pathlib import Path

def is_public_ip(ip: str) -> bool:
    """Check if an IP address is public."""
    return not any(ip.startswith(prefix) 
        for prefix in ('127.', '192.168.', '10.', '172.'))

def get_past_connections():
    """Get list of past public IP connections from system logs."""
    current_os = platform.system()
    ips = set()
    
    if current_os == 'Windows':
        cmd = [
            'powershell', 
            'Get-WinEvent -FilterHashtable @{LogName="Security"; Id=5156} -MaxEvents 1000 | Select-Object -Expand Message'
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            ips.update(re.findall(r'Source Address:\s+([\d.]+)', result.stdout))
        except subprocess.CalledProcessError:
            print("Error accessing Windows Security logs. Run as administrator.")
            
    elif current_os in ('Linux', 'Darwin'):
        log_paths = {
            'Linux': ['/var/log/syslog', '/var/log/auth.log'],
            'Darwin': ['/var/log/system.log']
        }
        for path in log_paths.get(current_os, []):
            try:
                with open(path, 'r') as f:
                    ips.update(re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', f.read()))
            except (PermissionError, FileNotFoundError):
                print(f"Error accessing {path}. Run with sudo.")
                
    return [ip for ip in ips if is_public_ip(ip)] 