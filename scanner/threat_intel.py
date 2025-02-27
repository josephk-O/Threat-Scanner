import os
import requests
import logging
import json
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("threat_intel.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("threat_intel")

load_dotenv()

def check_ip_abuse(ip: str, service='abuseipdb'):
    """Check IP against chosen threat intelligence service."""
    logger.info(f"Checking IP {ip} with service: {service}")
    if service == 'abuseipdb':
        return _check_abuseipdb(ip)
    elif service == 'virustotal':
        return _check_virustotal(ip)
    elif service == 'alienvault':
        return _check_alienvault(ip)
    elif service == 'both':
        return check_both_services(ip)
    elif service == 'all':
        return check_all_services(ip)
    else:
        raise ValueError("Invalid service specified")

def check_both_services(ip: str):
    """Check IP against both AbuseIPDB and VirusTotal."""
    logger.info(f"Checking IP {ip} with both services")
    abuseipdb_result = _check_abuseipdb(ip)
    virustotal_result = _check_virustotal(ip)
    
    return {
        'source': 'both',
        'abuseipdb': abuseipdb_result,
        'virustotal': virustotal_result
    }

def check_all_services(ip: str):
    """Check IP against all available threat intelligence services."""
    logger.info(f"Checking IP {ip} with all services")
    abuseipdb_result = _check_abuseipdb(ip)
    virustotal_result = _check_virustotal(ip)
    alienvault_result = _check_alienvault(ip)
    
    return {
        'source': 'all',
        'abuseipdb': abuseipdb_result,
        'virustotal': virustotal_result,
        'alienvault': alienvault_result
    }

def _check_abuseipdb(ip: str):
    """Check IP against AbuseIPDB."""
    logger.info(f"Checking IP {ip} with AbuseIPDB")
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        logger.error("AbuseIPDB API key not found in .env file")
        raise ValueError("AbuseIPDB API key not found in .env file")
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    
    try:
        logger.debug(f"Making request to AbuseIPDB: {url} with params: {params}")
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        result = response.json()
        logger.debug(f"AbuseIPDB response for {ip}: {json.dumps(result, indent=2)}")
        return {'source': 'abuseipdb', 'data': result['data']}
    except requests.exceptions.RequestException as e:
        logger.error(f"AbuseIPDB API error for {ip}: {str(e)}")
        return {'source': 'abuseipdb', 'error': f"API Error: {str(e)}"}

def _check_alienvault(ip: str):
    """Check IP against AlienVault OTX."""
    logger.info(f"Checking IP {ip} with AlienVault OTX")
    api_key = os.getenv('ALIENVAULT_API_KEY')
    if not api_key:
        logger.error("AlienVault API key not found in .env file")
        raise ValueError("AlienVault API key not found in .env file")
    
    try:
        # AlienVault OTX API endpoint for IP reputation
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json"
        }
        
        logger.debug(f"Making request to AlienVault OTX: {url}")
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        
        # Log the full response for debugging
        logger.debug(f"AlienVault OTX response for {ip}: {json.dumps(result, indent=2)}")
        
        # Get pulse data (threat intelligence reports)
        reputation_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"
        logger.debug(f"Making request to AlienVault OTX reputation: {reputation_url}")
        pulses_response = requests.get(reputation_url, headers=headers)
        pulses_response.raise_for_status()
        pulses_result = pulses_response.json()
        
        # Get geo data
        geo_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/geo"
        logger.debug(f"Making request to AlienVault OTX geo: {geo_url}")
        geo_response = requests.get(geo_url, headers=headers)
        geo_response.raise_for_status()
        geo_result = geo_response.json()
        
        # Get malware data
        malware_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/malware"
        logger.debug(f"Making request to AlienVault OTX malware: {malware_url}")
        malware_response = requests.get(malware_url, headers=headers)
        malware_response.raise_for_status()
        malware_result = malware_response.json()
        
        # Get URL list data
        url_list_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/url_list"
        logger.debug(f"Making request to AlienVault OTX url_list: {url_list_url}")
        url_list_response = requests.get(url_list_url, headers=headers)
        url_list_response.raise_for_status()
        url_list_result = url_list_response.json()
        
        # Get passive DNS data
        passive_dns_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
        logger.debug(f"Making request to AlienVault OTX passive_dns: {passive_dns_url}")
        passive_dns_response = requests.get(passive_dns_url, headers=headers)
        passive_dns_response.raise_for_status()
        passive_dns_result = passive_dns_response.json()
        
        # Get HTTP scans data
        http_scans_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/http_scans"
        logger.debug(f"Making request to AlienVault OTX http_scans: {http_scans_url}")
        http_scans_response = requests.get(http_scans_url, headers=headers)
        http_scans_response.raise_for_status()
        http_scans_result = http_scans_response.json()
        
        # Process the data
        pulse_count = pulses_result.get('count', 0)
        pulses = pulses_result.get('pulses', [])
        
        # Calculate threat score based on pulse count and reputation
        # Higher pulse count means more threat reports
        threat_score = min(100, pulse_count * 10)
        
        # Extract tags from pulses
        tags = []
        for pulse in pulses:
            tags.extend(pulse.get('tags', []))
        tags = list(set(tags))  # Remove duplicates
        
        # Extract malware families
        malware_families = []
        for malware in malware_result.get('data', []):
            if 'family' in malware:
                malware_families.append(malware['family'])
        malware_families = list(set(malware_families))  # Remove duplicates
        
        # Process URL list data
        associated_urls = []
        url_count = url_list_result.get('count', 0)
        url_data = url_list_result.get('url_list', [])
        if url_count > 0 and url_data:
            # Extract the top 10 URLs to avoid excessive data
            for url_entry in url_data[:10]:
                if 'url' in url_entry:
                    associated_urls.append(url_entry['url'])
        
        # Process passive DNS data
        dns_records = []
        dns_count = passive_dns_result.get('count', 0)
        dns_data = passive_dns_result.get('passive_dns', [])
        if dns_count > 0 and dns_data:
            # Extract the top 10 DNS records to avoid excessive data
            for dns_entry in dns_data[:10]:
                dns_record = {
                    'hostname': dns_entry.get('hostname', 'N/A'),
                    'record_type': dns_entry.get('record_type', 'N/A'),
                    'first_seen': dns_entry.get('first', 'N/A'),
                    'last_seen': dns_entry.get('last', 'N/A')
                }
                dns_records.append(dns_record)
        
        # Process HTTP scans data
        http_data = []
        http_count = http_scans_result.get('count', 0)
        scan_data = http_scans_result.get('data', [])
        if http_count > 0 and scan_data:
            # Extract the top 5 HTTP scans to avoid excessive data
            for scan in scan_data[:5]:
                http_entry = {
                    'date': scan.get('date', 'N/A'),
                    'method': scan.get('method', 'N/A'),
                    'url_port': scan.get('url_port', 'N/A'),
                    'http_status': scan.get('http_status', 'N/A'),
                    'server': scan.get('server', 'N/A'),
                    'content_type': scan.get('content_type', 'N/A')
                }
                http_data.append(http_entry)
        
        # Create processed data structure
        processed_data = {
            'source': 'alienvault',
            'data': {
                # General info
                'pulse_count': pulse_count,
                'threat_score': threat_score,
                'tags': tags,
                'malware_families': malware_families,
                
                # Geo information
                'country_name': geo_result.get('country_name', 'N/A'),
                'country_code': geo_result.get('country_code', 'N/A'),
                'city': geo_result.get('city', 'N/A'),
                'continent_code': geo_result.get('continent_code', 'N/A'),
                
                # Network information
                'asn': result.get('asn', 'N/A'),
                'isp': geo_result.get('asn', 'Unknown'),
                
                # Additional data
                'reputation': result.get('reputation', 0),
                'sections': result.get('sections', []),
                'malware_samples': len(malware_result.get('data', [])),
                'last_updated': result.get('whois', {}).get('updated', 'N/A') if isinstance(result.get('whois', {}), dict) else 'N/A',
                
                # URLs associated with this IP
                'url_count': url_count,
                'associated_urls': associated_urls,
                
                # Passive DNS information
                'dns_count': dns_count,
                'dns_records': dns_records,
                
                # HTTP scans information
                'http_scan_count': http_count,
                'http_scans': http_data
            }
        }
        
        logger.debug(f"Processed AlienVault data: {json.dumps(processed_data, indent=2)}")
        return processed_data
    except requests.exceptions.RequestException as e:
        logger.error(f"AlienVault API request error for {ip}: {str(e)}")
        return {'source': 'alienvault', 'error': f"API Error: {str(e)}"}
    except Exception as e:
        logger.error(f"AlienVault processing error for {ip}: {str(e)}", exc_info=True)
        return {'source': 'alienvault', 'error': f"Processing Error: {str(e)}"}

def _check_virustotal(ip: str):
    """Check IP against VirusTotal."""
    logger.info(f"Checking IP {ip} with VirusTotal")
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        logger.error("VirusTotal API key not found in .env file")
        raise ValueError("VirusTotal API key not found in .env file")
    
    try:
        # Using requests directly for API v3
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        logger.debug(f"Making request to VirusTotal: {url}")
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        
        # Log the full response for debugging
        logger.debug(f"VirusTotal response for {ip}: {json.dumps(result, indent=2)}")
        
        # Check if we have a valid response structure
        if 'data' not in result or 'attributes' not in result.get('data', {}):
            logger.error(f"Invalid VirusTotal API response format for {ip}: {json.dumps(result, indent=2)}")
            return {
                'source': 'virustotal',
                'error': "Invalid API response format"
            }
        
        # Extract data from the new API v3 response format
        attributes = result.get('data', {}).get('attributes', {})
        
        # Check if last_analysis_stats exists
        if 'last_analysis_stats' not in attributes:
            logger.warning(f"No last_analysis_stats in VirusTotal response for {ip}")
            # Create default stats
            last_analysis_stats = {
                'malicious': 0,
                'suspicious': 0,
                'harmless': 0,
                'undetected': 0,
                'timeout': 0
            }
        else:
            last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        logger.debug(f"Extracted attributes: {json.dumps(attributes, indent=2)}")
        logger.debug(f"Last analysis stats: {json.dumps(last_analysis_stats, indent=2)}")
        
        # Create a more comprehensive data structure with additional attributes
        processed_data = {
            'source': 'virustotal',
            'data': {
                # Analysis stats
                'malicious': last_analysis_stats.get('malicious', 0),
                'suspicious': last_analysis_stats.get('suspicious', 0),
                'harmless': last_analysis_stats.get('harmless', 0),
                'undetected': last_analysis_stats.get('undetected', 0),
                'timeout': last_analysis_stats.get('timeout', 0),
                
                # Location and network information
                'country': attributes.get('country', 'N/A'),
                'continent': attributes.get('continent', 'N/A'),
                'as_owner': attributes.get('as_owner', 'Unknown'),
                'asn': attributes.get('asn', 'N/A'),
                'network': attributes.get('network', 'N/A'),
                'regional_internet_registry': attributes.get('regional_internet_registry', 'N/A'),
                
                # Reputation and categorization
                'reputation': attributes.get('reputation', 0),
                'tags': attributes.get('tags', []),
                'last_analysis_date': attributes.get('last_analysis_date', 0),
                'last_modification_date': attributes.get('last_modification_date', 0),
            }
        }
        
        # Ensure all values are of the expected type
        for key, value in processed_data['data'].items():
            if key in ['malicious', 'suspicious', 'harmless', 'undetected', 'timeout']:
                try:
                    processed_data['data'][key] = int(value)
                except (ValueError, TypeError):
                    logger.warning(f"Converting {key} value '{value}' to 0")
                    processed_data['data'][key] = 0
        
        logger.debug(f"Processed VirusTotal data: {json.dumps(processed_data, indent=2)}")
        return processed_data
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal API request error for {ip}: {str(e)}")
        return {'source': 'virustotal', 'error': f"API Error: {str(e)}"}
    except Exception as e:
        logger.error(f"VirusTotal processing error for {ip}: {str(e)}", exc_info=True)
        return {'source': 'virustotal', 'error': f"Processing Error: {str(e)}"} 