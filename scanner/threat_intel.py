import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from time import perf_counter, sleep
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv

from handlers.threat_logging import ThreatScanLogger


logger = ThreatScanLogger("threat_intel", logger_level='DEBUG')

load_dotenv()


SERVICE_LABELS = {
    'abuseipdb': 'AbuseIPDB',
    'virustotal': 'VirusTotal',
    'alienvault': 'AlienVault OTX',
    'both': 'AbuseIPDB & VirusTotal',
    'all': 'All services',
}


def _resolve_service_label(service: str) -> str:
    return SERVICE_LABELS.get(service.lower(), service)


def _abuseipdb_threat_score(result: Dict[str, Any], ip: str, log_event: bool = True) -> int:
    if not isinstance(result, dict) or result.get('error'):
        return 0

    data = result.get('data', {}) if isinstance(result.get('data'), dict) else {}
    score_raw = data.get('abuseConfidenceScore', 0)
    try:
        score = int(score_raw)
    except (TypeError, ValueError):
        score = 0

    if score <= 0:
        return 0

    if score >= 75:
        severity = 'HIGH'
    elif score >= 40:
        severity = 'MEDIUM'
    else:
        severity = 'LOW'

    if log_event:
        logger.threat_detected(
            'AbuseIPDB',
            severity,
            {
                'ip': ip,
                'confidence_score': score,
                'total_reports': data.get('totalReports', 0),
            },
        )

    return 1


def _virustotal_threat_score(result: Dict[str, Any], ip: str, log_event: bool = True) -> int:
    if not isinstance(result, dict) or result.get('error'):
        return 0

    data = result.get('data', {}) if isinstance(result.get('data'), dict) else {}
    malicious = _coerce_int(data.get('malicious', 0))
    suspicious = _coerce_int(data.get('suspicious', 0))
    total = malicious + suspicious

    if total == 0:
        return 0

    severity = 'HIGH' if malicious else 'MEDIUM'

    if log_event:
        logger.threat_detected(
            'VirusTotal',
            severity,
            {
                'ip': ip,
                'malicious': malicious,
                'suspicious': suspicious,
                'reputation': data.get('reputation', 0),
            },
        )

    return total


def _alienvault_threat_score(result: Dict[str, Any], ip: str, log_event: bool = True) -> int:
    if not isinstance(result, dict) or result.get('error'):
        return 0

    data = result.get('data', {}) if isinstance(result.get('data'), dict) else {}
    threat_score = _coerce_int(data.get('threat_score', 0))
    pulse_count = _coerce_int(data.get('pulse_count', 0))

    if not threat_score and not pulse_count:
        return 0

    if threat_score >= 80 or pulse_count >= 8:
        severity = 'HIGH'
    elif threat_score >= 50 or pulse_count >= 4:
        severity = 'MEDIUM'
    else:
        severity = 'LOW'

    if log_event:
        logger.threat_detected(
            'AlienVault OTX',
            severity,
            {
                'ip': ip,
                'threat_score': threat_score,
                'pulse_count': pulse_count,
                'malware_families': data.get('malware_families', []),
            },
        )

    return max(pulse_count, 1) if pulse_count or threat_score else 0


def _coerce_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _collect_threats(service: str, ip: str, result: Dict[str, Any]) -> int:
    service_key = (service or '').lower()

    if not isinstance(result, dict) or result.get('error'):
        return 0

    if service_key == 'abuseipdb':
        return _abuseipdb_threat_score(result, ip, log_event=False)
    if service_key == 'virustotal':
        return _virustotal_threat_score(result, ip, log_event=False)
    if service_key == 'alienvault':
        return _alienvault_threat_score(result, ip, log_event=False)
    if service_key == 'both':
        abuse = result.get('abuseipdb', {})
        virus = result.get('virustotal', {})
        return (
            _abuseipdb_threat_score(abuse, ip, log_event=False) +
            _virustotal_threat_score(virus, ip, log_event=False)
        )
    if service_key == 'all':
        abuse = result.get('abuseipdb', {})
        virus = result.get('virustotal', {})
        alien = result.get('alienvault', {})
        return (
            _abuseipdb_threat_score(abuse, ip, log_event=False) +
            _virustotal_threat_score(virus, ip, log_event=False) +
            _alienvault_threat_score(alien, ip, log_event=False)
        )

    return 0

def check_ip_abuse(ip: str, service: str = 'abuseipdb') -> Dict[str, Any]:
    """Check IP against chosen threat intelligence service."""

    normalized_service = (service or 'abuseipdb').lower()
    service_label = _resolve_service_label(normalized_service)

    logger.scan_started(ip, service_label)
    start_time = perf_counter()
    threats_found = 0

    try:
        if normalized_service == 'abuseipdb':
            result = _check_abuseipdb(ip)
        elif normalized_service == 'virustotal':
            result = _check_virustotal(ip)
        elif normalized_service == 'alienvault':
            result = _check_alienvault(ip)
        elif normalized_service == 'both':
            result = {
                'source': 'both',
                'abuseipdb': _check_abuseipdb(ip),
                'virustotal': _check_virustotal(ip),
            }
        elif normalized_service == 'all':
            result = {
                'source': 'all',
                'abuseipdb': _check_abuseipdb(ip),
                'virustotal': _check_virustotal(ip),
                'alienvault': _check_alienvault(ip),
            }
        else:
            raise ValueError("Invalid service specified")

        threats_found = _collect_threats(normalized_service, ip, result)
        return result
    except Exception as exc:
        logger.error(f"Error checking IP {ip}: {str(exc)}")
        return {
            'source': normalized_service,
            'error': f"Check Error: {str(exc)}",
        }
    finally:
        duration = perf_counter() - start_time
        logger.scan_completed(ip, threats_found, duration)


def check_both_services(ip: str) -> Dict[str, Any]:
    """Check IP against both AbuseIPDB and VirusTotal."""

    return check_ip_abuse(ip, service='both')


def check_all_services(ip: str) -> Dict[str, Any]:
    """Check IP against all available threat intelligence services."""

    return check_ip_abuse(ip, service='all')

def scan_ips_parallel(
    ip_list: List[str],
    service: str = 'all',
    max_workers: int = 10,
    progress_callback=None,
) -> Dict[str, Any]:
    """
    Scan multiple IPs in parallel using ThreadPoolExecutor.

    Args:
        ip_list: List of IP addresses to scan.
        service: Service to use ('all', 'both', 'abuseipdb', 'virustotal', or 'alienvault').
        max_workers: Maximum number of concurrent threads.
        progress_callback: Optional callback with signature (ip, completed, total).

    Returns:
        Dictionary containing aggregated stats and per-IP scan results.
    """

    service_label = _resolve_service_label(service)
    total_targets = len(ip_list)

    logger.scan_started(
        f"{total_targets} targets",
        f"parallel scan using {service_label} with {max_workers} workers",
    )

    start_time = perf_counter()
    threats_found = 0
    results: Dict[str, Any] = {}
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(check_ip_abuse, ip, service): ip
            for ip in ip_list
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                results[ip] = future.result()
                threats_found += _collect_threats(service, ip, results[ip])
                logger.debug(f"Completed scan for IP: {ip}")
            except Exception as scan_error:
                logger.error(f"Error scanning IP {ip}: {scan_error}")
                results[ip] = {
                    'source': service,
                    'error': f"Scan Error: {scan_error}",
                }
            finally:
                completed += 1
                if progress_callback:
                    try:
                        progress_callback(ip, completed, total_targets or completed)
                    except Exception as progress_error:
                        logger.error(
                            f"Error in progress callback for {ip}: {progress_error}"
                        )

    duration = perf_counter() - start_time
    logger.scan_completed(f"{total_targets} targets", threats_found, duration)

    successful_ips = [
        ip for ip in ip_list if ip in results and 'error' not in results[ip]
    ]
    failed_ips = [
        ip for ip in ip_list if ip in results and 'error' in results[ip]
    ]

    return {
        'stats': {
            'active_ips': len(successful_ips),
            'failed_ips': len(failed_ips),
            'total_ips': total_targets,
            'threats_found': threats_found,
            'message': (
                f"Scanned {total_targets} IPs ({len(successful_ips)} successful)"
                if total_targets
                else "No IPs scanned"
            ),
        },
        'results': results,
    }

# Rate limiting for API calls
def rate_limit(calls: int, period: float):
    """
    Decorator to implement rate limiting.
    
    Args:
        calls: Number of calls allowed
        period: Time period in seconds
    """
    from collections import deque
    from time import time
    
    timestamps = deque(maxlen=calls)
    
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time()
            
            # Remove timestamps older than our period
            while timestamps and timestamps[0] < now - period:
                timestamps.popleft()
            
            # If we've hit our limit, sleep until oldest timestamp expires
            if len(timestamps) == calls:
                sleep_time = timestamps[0] - (now - period)
                if sleep_time > 0:
                    sleep(sleep_time)
            
            timestamps.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Apply rate limiting to API calls
@logger.timed_scan(
    service='AbuseIPDB',
    target_resolver=lambda ip, **_: ip,
    threat_counter=lambda result, target, _: _abuseipdb_threat_score(result, target),
)
@rate_limit(calls=60, period=60)  # 60 calls per minute for AbuseIPDB
def _check_abuseipdb(ip: str) -> Dict[str, Any]:
    """Rate-limited version of AbuseIPDB check"""
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        logger.error("AbuseIPDB API key not found in .env file")
        raise ValueError("AbuseIPDB API key not found in .env file")
    
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': api_key, 'Accept': 'application/json'}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    
    try:
        # logger.debug(f"Making request to AbuseIPDB: {url} with params: {params}")
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        result = response.json()
        # logger.debug(f"AbuseIPDB response for {ip}: {json.dumps(result, indent=2)}")
        return {'source': 'abuseipdb', 'data': result['data']}
    except requests.exceptions.RequestException as e:
        logger.error(f"AbuseIPDB API error for {ip}: {str(e)}")
        return {'source': 'abuseipdb', 'error': f"API Error: {str(e)}"}

@logger.timed_scan(
    service='VirusTotal',
    target_resolver=lambda ip, **_: ip,
    threat_counter=lambda result, target, _: _virustotal_threat_score(result, target),
)
@rate_limit(calls=4, period=60)  # 4 calls per minute for VirusTotal free tier
def _check_virustotal(ip: str) -> Dict[str, Any]:
    """Rate-limited version of VirusTotal check"""
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        logger.error("VirusTotal API key not found in .env file")
        raise ValueError("VirusTotal API key not found in .env file")
    
    try:
     
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }
        
        # logger.debug(f"Making request to VirusTotal: {url}")
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        
        # Log the full response for debugging
        # logger.debug(f"VirusTotal response for {ip}: {json.dumps(result, indent=2)}")
        
        # Check if we have a valid response structure
        if 'data' not in result or 'attributes' not in result.get('data', {}):
            # logger.error(f"Invalid VirusTotal API response format for {ip}: {json.dumps(result, indent=2)}")
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
        
        # logger.debug(f"Extracted attributes: {json.dumps(attributes, indent=2)}")
        # logger.debug(f"Last analysis stats: {json.dumps(last_analysis_stats, indent=2)}")
        
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
        
        # logger.debug(f"Processed VirusTotal data: {json.dumps(processed_data, indent=2)}")
        return processed_data
    except requests.exceptions.RequestException as e:
        logger.error(f"VirusTotal API request error for {ip}: {str(e)}")
        return {'source': 'virustotal', 'error': f"API Error: {str(e)}"}
    except Exception as e:
        logger.error(f"VirusTotal processing error for {ip}: {str(e)}", exc_info=True)
        return {'source': 'virustotal', 'error': f"Processing Error: {str(e)}"}

@logger.timed_scan(
    service='AlienVault OTX',
    target_resolver=lambda ip, **_: ip,
    threat_counter=lambda result, target, _: _alienvault_threat_score(result, target),
)
@rate_limit(calls=10, period=60)  # 10 calls per minute for AlienVault OTX
def _check_alienvault(ip: str) -> Dict[str, Any]:
    """Rate-limited version of AlienVault check"""
    api_key = os.getenv('ALIENVAULT_API_KEY')
    if not api_key:
        logger.error("AlienVault API key not found in .env file")
        raise ValueError("AlienVault API key not found in .env file")
    
    
    
    try:
        # AlienVault OTX API endpoint for IP reputation
        # url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        url = _get_otx_url(ip)
        headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json"
        }
        
        # logger.debug(f"Making request to AlienVault OTX: {url}")
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()
        
        # Log the full response for debugging
        # logger.debug(f"AlienVault OTX response for {ip}: {json.dumps(result, indent=2)}")
        
        # Get pulse data (threat intelligence reports)
        reputation_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"
        # logger.debug(f"Making request to AlienVault OTX reputation: {reputation_url}")
        pulses_response = requests.get(reputation_url, headers=headers)
        pulses_response.raise_for_status()
        pulses_result = pulses_response.json()
        
        # Get geo data
        geo_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/geo"
        # logger.debug(f"Making request to AlienVault OTX geo: {geo_url}")
        geo_response = requests.get(geo_url, headers=headers)
        geo_response.raise_for_status()
        geo_result = geo_response.json()
        
        # Get malware data
        malware_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/malware"
        # logger.debug(f"Making request to AlienVault OTX malware: {malware_url}")
        malware_response = requests.get(malware_url, headers=headers)
        malware_response.raise_for_status()
        malware_result = malware_response.json()
        
        # Get URL list data
        url_list_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/url_list"
        # logger.debug(f"Making request to AlienVault OTX url_list: {url_list_url}")
        url_list_response = requests.get(url_list_url, headers=headers)
        url_list_response.raise_for_status()
        url_list_result = url_list_response.json()
        
        # Get passive DNS data
        passive_dns_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"
        # logger.debug(f"Making request to AlienVault OTX passive_dns: {passive_dns_url}")
        passive_dns_response = requests.get(passive_dns_url, headers=headers)
        passive_dns_response.raise_for_status()
        passive_dns_result = passive_dns_response.json()
        
        # Get HTTP scans data
        http_scans_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/http_scans"
        # logger.debug(f"Making request to AlienVault OTX http_scans: {http_scans_url}")
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
        
        # logger.debug(f"Processed AlienVault data: {json.dumps(processed_data, indent=2)}")
        return processed_data
    except requests.exceptions.RequestException as e:
        logger.error(f"AlienVault API request error for {ip}: {str(e)}")
        return {'source': 'alienvault', 'error': f"API Error: {str(e)}"}
    except Exception as e:
        logger.error(f"AlienVault processing error for {ip}: {str(e)}", exc_info=True)
        return {'source': 'alienvault', 'error': f"Processing Error: {str(e)}"} 

import ipaddress

def _get_otx_url(ip: str) -> str:
    """Returns the correct AlienVault OTX API URL for IPv4 or IPv6."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        ip_type = "IPv6" if ip_obj.version == 6 else "IPv4"
        url = f"https://otx.alienvault.com/api/v1/indicators/{ip_type}/{ip}/general"
        logger.error(url)
        return url
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip}")