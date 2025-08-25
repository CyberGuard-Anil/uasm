"""
Input validators for UASM
Validation functions for user inputs and data
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional, List, Union


def validate_target(target: str) -> bool:
    """Validate scan target (IP, CIDR, domain, or URL)"""
    if not target or not isinstance(target, str):
        return False
    
    target = target.strip()
    
    # Check if it's an IP address
    if validate_ip_address(target):
        return True
    
    # Check if it's a CIDR range
    if validate_cidr_range(target):
        return True
    
    # Check if it's a domain
    if validate_domain(target):
        return True
    
    # Check if it's a URL
    if validate_url(target):
        return True
    
    return False


def validate_ip_address(ip: str) -> bool:
    """Validate IP address (IPv4 or IPv6)"""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def validate_cidr_range(cidr: str) -> bool:
    """Validate CIDR range"""
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        # Limit network size for safety
        if network.num_addresses > 65536:  # /16 for IPv4
            return False
        return True
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False


def validate_domain(domain: str) -> bool:
    """Validate domain name"""
    if not domain or len(domain) > 253:
        return False
    
    domain = domain.strip().lower()
    
    # Remove protocol if present
    if domain.startswith(('http://', 'https://')):
        try:
            domain = urlparse(domain).hostname
        except:
            return False
    
    if not domain:
        return False
    
    # Domain name regex
    domain_pattern = re.compile(
        r'^(?=.{1,253}$)(?=.{1,63}\.)*(?![0-9]+$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$'
    )
    
    return bool(domain_pattern.match(domain))


def validate_url(url: str) -> bool:
    """Validate URL"""
    try:
        result = urlparse(url.strip())
        return all([result.scheme, result.netloc]) and result.scheme in ['http', 'https']
    except Exception:
        return False


def validate_port(port: Union[str, int]) -> bool:
    """Validate port number"""
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_port_range(port_range: str) -> bool:
    """Validate port range string (e.g., '80,443,1000-2000')"""
    if not port_range or not isinstance(port_range, str):
        return False
    
    parts = port_range.split(',')
    
    for part in parts:
        part = part.strip()
        
        if '-' in part:
            # Range like '1000-2000'
            try:
                start, end = part.split('-')
                start_port = int(start.strip())
                end_port = int(end.strip())
                
                if not (validate_port(start_port) and validate_port(end_port)):
                    return False
                
                if start_port > end_port:
                    return False
                    
                # Limit range size
                if (end_port - start_port) > 10000:
                    return False
                    
            except ValueError:
                return False
        else:
            # Single port
            if not validate_port(part):
                return False
    
    return True


def validate_thread_count(threads: Union[str, int]) -> bool:
    """Validate thread count"""
    try:
        thread_count = int(threads)
        return 1 <= thread_count <= 1000
    except (ValueError, TypeError):
        return False


def validate_timeout(timeout: Union[str, int, float]) -> bool:
    """Validate timeout value in seconds"""
    try:
        timeout_val = float(timeout)
        return 1 <= timeout_val <= 3600  # 1 second to 1 hour
    except (ValueError, TypeError):
        return False


def validate_file_path(file_path: str) -> bool:
    """Validate file path"""
    if not file_path or not isinstance(file_path, str):
        return False
    
    try:
        from pathlib import Path
        path = Path(file_path.strip())
        
        # Check for directory traversal
        if '..' in str(path):
            return False
        
        # Check if parent directory exists or can be created
        if path.parent.exists() or path.parent == Path('.'):
            return True
        
        return False
    except Exception:
        return False


def validate_output_format(format_str: str) -> bool:
    """Validate output format"""
    valid_formats = ['html', 'json', 'csv', 'markdown', 'pdf', 'xml']
    
    if not format_str or not isinstance(format_str, str):
        return False
    
    formats = [f.strip().lower() for f in format_str.split(',')]
    
    return all(fmt in valid_formats for fmt in formats)


def validate_config_value(key: str, value) -> bool:
    """Validate configuration value based on key"""
    validation_rules = {
        'threads': lambda v: validate_thread_count(v),
        'timeout': lambda v: validate_timeout(v),
        'max_threads': lambda v: validate_thread_count(v),
        'scan_timeout': lambda v: validate_timeout(v),
        'port': lambda v: validate_port(v),
        'ports': lambda v: validate_port_range(str(v)) if not isinstance(v, list) else all(validate_port(p) for p in v),
        'rate_limit': lambda v: isinstance(v, (int, float)) and v > 0,
        'max_redirects': lambda v: isinstance(v, int) and 0 <= v <= 20,
    }
    
    # Generic validations based on key patterns
    if 'timeout' in key.lower():
        return validate_timeout(value)
    elif 'thread' in key.lower():
        return validate_thread_count(value)
    elif 'port' in key.lower():
        return validate_port(value) if isinstance(value, (int, str)) else True
    elif key in validation_rules:
        return validation_rules[key](value)
    
    # Default validation - check for reasonable types
    return value is not None


def validate_wordlist_file(file_path: str) -> bool:
    """Validate wordlist file"""
    if not validate_file_path(file_path):
        return False
    
    try:
        from pathlib import Path
        path = Path(file_path)
        
        if not path.exists():
            return False
        
        if not path.is_file():
            return False
        
        # Check file size (reasonable limit)
        if path.stat().st_size > 100 * 1024 * 1024:  # 100MB
            return False
        
        # Try to read first few lines
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()[:10]
            return len(lines) > 0
            
    except Exception:
        return False


def validate_user_agent(user_agent: str) -> bool:
    """Validate user agent string"""
    if not user_agent or not isinstance(user_agent, str):
        return False
    
    user_agent = user_agent.strip()
    
    # Basic checks
    if len(user_agent) < 10 or len(user_agent) > 500:
        return False
    
    # Should contain typical user agent components
    required_components = ['Mozilla', 'AppleWebKit', 'Chrome', 'Safari', 'Firefox', 'Edge']
    
    return any(component in user_agent for component in required_components)


def validate_severity_level(severity: str) -> bool:
    """Validate vulnerability severity level"""
    valid_severities = ['critical', 'high', 'medium', 'low', 'info', 'informational']
    
    if not severity or not isinstance(severity, str):
        return False
    
    return severity.lower().strip() in valid_severities


def validate_cvss_score(score: Union[str, int, float]) -> bool:
    """Validate CVSS score"""
    try:
        score_val = float(score)
        return 0.0 <= score_val <= 10.0
    except (ValueError, TypeError):
        return False


def validate_email(email: str) -> bool:
    """Validate email address"""
    if not email or not isinstance(email, str):
        return False
    
    email_pattern = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    return bool(email_pattern.match(email.strip()))


def validate_api_key(api_key: str) -> bool:
    """Validate API key format"""
    if not api_key or not isinstance(api_key, str):
        return False
    
    api_key = api_key.strip()
    
    # Basic checks
    if len(api_key) < 16 or len(api_key) > 128:
        return False
    
    # Should be alphanumeric with possible special characters
    api_key_pattern = re.compile(r'^[a-zA-Z0-9\-_\.]+$')
    
    return bool(api_key_pattern.match(api_key))


def validate_regex_pattern(pattern: str) -> bool:
    """Validate regex pattern"""
    if not pattern or not isinstance(pattern, str):
        return False
    
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def sanitize_input(input_str: str, max_length: int = 1000) -> str:
    """Sanitize input string"""
    if not isinstance(input_str, str):
        return ""
    
    # Remove null bytes and control characters
    sanitized = ''.join(char for char in input_str if ord(char) >= 32 or char in ['\n', '\r', '\t'])
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()


def validate_scan_modules(modules: List[str]) -> bool:
    """Validate scan modules list"""
    valid_modules = ['network', 'web', 'api', 'cloud']
    
    if not modules or not isinstance(modules, list):
        return False
    
    return all(module in valid_modules for module in modules)


def validate_database_config(db_config: dict) -> bool:
    """Validate database configuration"""
    if not isinstance(db_config, dict):
        return False
    
    db_type = db_config.get('type', '').lower()
    valid_types = ['sqlite', 'postgresql', 'mysql']
    
    if db_type not in valid_types:
        return False
    
    if db_type != 'sqlite':
        # Network databases require host and port
        host = db_config.get('host')
        port = db_config.get('port')
        
        if not host or not validate_port(port):
            return False
    
    return True


def is_safe_filename(filename: str) -> bool:
    """Check if filename is safe for filesystem"""
    if not filename or not isinstance(filename, str):
        return False
    
    # Check for dangerous patterns
    dangerous_patterns = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
    
    for pattern in dangerous_patterns:
        if pattern in filename:
            return False
    
    # Check length
    if len(filename) > 255:
        return False
    
    # Check for reserved names (Windows)
    reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
                     'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 
                     'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']
    
    name_without_ext = filename.split('.')[0].upper()
    if name_without_ext in reserved_names:
        return False
    
    return True


def validate_json_data(json_str: str) -> bool:
    """Validate JSON string"""
    if not json_str or not isinstance(json_str, str):
        return False
    
    try:
        import json
        json.loads(json_str)
        return True
    except (json.JSONDecodeError, ValueError):
        return False

