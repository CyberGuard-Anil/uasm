"""
Helper utilities for UASM
Common utility functions used across modules
"""

import os
import re
import time
import socket
import random
import string
from pathlib import Path
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse
import dns.resolver


def generate_user_agent() -> str:
    """Generate a random user agent string"""
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
    ]
    return random.choice(user_agents)


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_valid_domain(domain: str) -> bool:
    """Check if string is a valid domain name"""
    if not domain or len(domain) > 253:
        return False
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        domain = urlparse(domain).hostname
    
    # Basic domain regex
    domain_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    
    return bool(domain_regex.match(domain))


def resolve_domain(domain: str) -> Optional[str]:
    """Resolve domain name to IP address"""
    try:
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            domain = urlparse(domain).hostname
        
        result = dns.resolver.resolve(domain, 'A')
        return str(result[0])
    except:
        return None


def clean_domain(domain: str) -> str:
    """Clean domain name by removing protocol and path"""
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        return parsed.hostname or parsed.netloc
    return domain.strip().lower()


def generate_output_dir(target: str) -> str:
    """Generate output directory name for target"""
    # Clean target name for filesystem
    clean_target = sanitize_filename(target)
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    return f"scans/{clean_target}_{timestamp}"


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for filesystem compatibility"""
    # Remove or replace invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'[^\w\-_\.]', '_', filename)
    filename = re.sub(r'_+', '_', filename)  # Multiple underscores to single
    filename = filename.strip('_.')  # Remove leading/trailing underscores and dots
    
    # Limit length
    if len(filename) > 100:
        filename = filename[:100]
    
    return filename or 'unknown'


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human readable string"""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def generate_random_string(length: int = 10) -> str:
    """Generate random string"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def is_private_ip(ip: str) -> bool:
    """Check if IP address is private"""
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private
    except:
        return False


def get_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        return urlparse(url).hostname
    except:
        return None


def create_directory(path: str) -> bool:
    """Create directory if it doesn't exist"""
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


def read_wordlist(filepath: str) -> List[str]:
    """Read wordlist from file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception:
        return []


def write_json_file(data: Dict[str, Any], filepath: str) -> bool:
    """Write data to JSON file"""
    try:
        import json
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception:
        return False


def read_json_file(filepath: str) -> Optional[Dict[str, Any]]:
    """Read JSON file"""
    try:
        import json
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def get_file_size(filepath: str) -> int:
    """Get file size in bytes"""
    try:
        return os.path.getsize(filepath)
    except:
        return 0


def is_url_accessible(url: str, timeout: int = 10) -> bool:
    """Check if URL is accessible"""
    try:
        import requests
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        return response.status_code < 400
    except:
        return False


def extract_ips_from_text(text: str) -> List[str]:
    """Extract IP addresses from text"""
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    return ip_pattern.findall(text)


def extract_domains_from_text(text: str) -> List[str]:
    """Extract domain names from text"""
    domain_pattern = re.compile(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*(com|net|org|edu|gov|mil|int|co|io|dev|app|tech|info|biz|name|pro|mobi|travel|museum|[a-z]{2})\b')
    return [match[0] + '.' + match[1] + match[2] for match in domain_pattern.findall(text)]


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of string"""
    if not data:
        return 0
    
    import math
    from collections import Counter
    
    counts = Counter(data)
    length = len(data)
    
    entropy = 0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def is_base64(s: str) -> bool:
    """Check if string is base64 encoded"""
    try:
        import base64
        if len(s) % 4 == 0:
            base64.b64decode(s, validate=True)
            return True
    except:
        pass
    return False


def decode_base64(s: str) -> Optional[str]:
    """Decode base64 string"""
    try:
        import base64
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except:
        return None


def get_current_timestamp() -> str:
    """Get current timestamp as ISO string"""
    from datetime import datetime
    return datetime.now().isoformat()


def parse_port_range(port_range: str) -> List[int]:
    """Parse port range string to list of ports"""
    ports = []
    
    for part in port_range.split(','):
        part = part.strip()
        
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            except:
                continue
        else:
            try:
                ports.append(int(part))
            except:
                continue
    
    return sorted(list(set(ports)))


def merge_dictionaries(dict1: Dict, dict2: Dict) -> Dict:
    """Deep merge two dictionaries"""
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dictionaries(result[key], value)
        else:
            result[key] = value
    
    return result


def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Split list into chunks of specified size"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def retry_on_failure(func, max_retries: int = 3, delay: float = 1.0):
    """Retry function on failure with exponential backoff"""
    import time
    
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            time.sleep(delay * (2 ** attempt))
    
    return None


def get_system_info() -> Dict[str, str]:
    """Get basic system information"""
    import platform
    
    return {
        'system': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version()
    }


def find_files_with_extension(directory: str, extension: str) -> List[str]:
    """Find all files with specified extension in directory"""
    files = []
    try:
        for file_path in Path(directory).rglob(f"*.{extension}"):
            files.append(str(file_path))
    except:
        pass
    return files


def hash_string(s: str, algorithm: str = 'sha256') -> str:
    """Hash string using specified algorithm"""
    import hashlib
    
    hash_obj = hashlib.new(algorithm)
    hash_obj.update(s.encode('utf-8'))
    return hash_obj.hexdigest()


def is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if port is open on host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def get_open_ports(host: str, ports: List[int], timeout: float = 3.0) -> List[int]:
    """Get list of open ports on host"""
    open_ports = []
    
    for port in ports:
        if is_port_open(host, port, timeout):
            open_ports.append(port)
    
    return open_ports

