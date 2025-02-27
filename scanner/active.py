import psutil
import platform
import sys

def is_public_ip(ip: str) -> bool:
    """Check if an IP address is public."""
    return not any(ip.startswith(prefix) 
        for prefix in ('127.', '192.168.', '10.', '172.'))

def get_active_connections():
    """Get list of active public IP connections."""
    connections = set()
    
    try:
        for conn in psutil.net_connections():
            if conn.raddr and conn.status == 'ESTABLISHED':
                ip = conn.raddr.ip
                if ip and is_public_ip(ip):
                    connections.add(ip)
    except psutil.AccessDenied:
        current_os = platform.system()
        if current_os == 'Darwin':  # macOS
            print("Error: Permission denied. Please run with sudo:")
            print("sudo -E python main.py")
        elif current_os == 'Linux':
            print("Error: Permission denied. Please run with sudo:")
            print("sudo -E python main.py")
        elif current_os == 'Windows':
            print("Error: Permission denied. Please run as Administrator")
        sys.exit(1)
    except Exception as e:
        print(f"Error accessing network connections: {str(e)}")
        return []
        
    return list(connections) 