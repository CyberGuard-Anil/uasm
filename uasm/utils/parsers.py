"""
Data parsers for UASM
Functions to parse various data formats and responses
"""

import re
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import base64


def parse_nmap_xml(xml_content: str) -> Dict[str, Any]:
    """Parse Nmap XML output"""
    try:
        root = ET.fromstring(xml_content)
        
        hosts = []
        
        for host in root.findall('host'):
            host_data = {
                'ip_address': '',
                'hostname': '',
                'status': 'unknown',
                'ports': [],
                'os_info': {}
            }
            
            # Get IP address
            address = host.find('address')
            if address is not None:
                host_data['ip_address'] = address.get('addr', '')
            
            # Get hostname
            hostnames = host.find('hostnames')
            if hostnames is not None:
                hostname = hostnames.find('hostname')
                if hostname is not None:
                    host_data['hostname'] = hostname.get('name', '')
            
            # Get status
            status = host.find('status')
            if status is not None:
                host_data['status'] = status.get('state', 'unknown')
            
            # Get ports
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    port_data = {
                        'port': int(port.get('portid', 0)),
                        'protocol': port.get('protocol', 'tcp'),
                        'state': 'closed',
                        'service': 'unknown',
                        'product': '',
                        'version': ''
                    }
                    
                    # Port state
                    state = port.find('state')
                    if state is not None:
                        port_data['state'] = state.get('state', 'closed')
                    
                    # Service info
                    service = port.find('service')
                    if service is not None:
                        port_data['service'] = service.get('name', 'unknown')
                        port_data['product'] = service.get('product', '')
                        port_data['version'] = service.get('version', '')
                    
                    host_data['ports'].append(port_data)
            
            # Get OS info
            os_elem = host.find('os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    host_data['os_info'] = {
                        'name': osmatch.get('name', ''),
                        'accuracy': osmatch.get('accuracy', ''),
                        'family': osmatch.get('osfamily', '')
                    }
            
            hosts.append(host_data)
        
        return {
            'hosts': hosts,
            'scan_info': {
                'scanner': 'nmap',
                'version': root.get('version', ''),
                'scan_type': root.get('args', '')
            }
        }
        
    except Exception as e:
        return {'error': f'Failed to parse Nmap XML: {str(e)}', 'hosts': []}


def parse_service_banner(banner: str) -> Dict[str, str]:
    """Parse service banner to extract product and version info"""
    if not banner:
        return {'product': '', 'version': ''}
    
    banner = banner.strip()
    
    # Common service patterns
    patterns = [
        # SSH
        (r'SSH-[\d\.]+-OpenSSH_([\d\.]+)', {'product': 'OpenSSH', 'version': r'\1'}),
        (r'SSH-[\d\.]+-(\w+)_([\d\.]+)', {'product': r'\1', 'version': r'\2'}),
        
        # HTTP servers
        (r'Server: ([^/\s]+)/?([\d\.]+)?', {'product': r'\1', 'version': r'\2'}),
        (r'nginx/([\d\.]+)', {'product': 'nginx', 'version': r'\1'}),
        (r'Apache/([\d\.]+)', {'product': 'Apache', 'version': r'\1'}),
        (r'Microsoft-IIS/([\d\.]+)', {'product': 'IIS', 'version': r'\1'}),
        
        # FTP
        (r'220[^\r\n]*([^\s]+)\s+FTP.*?v?([\d\.]+)', {'product': r'\1 FTP', 'version': r'\2'}),
        (r'220.*?vsftpd\s+([\d\.]+)', {'product': 'vsftpd', 'version': r'\1'}),
        
        # SMTP
        (r'220[^\r\n]*([^\s]+)\s+ESMTP.*?v?([\d\.]+)', {'product': r'\1 SMTP', 'version': r'\2'}),
        
        # Database
        (r'MySQL.*?([\d\.]+)', {'product': 'MySQL', 'version': r'\1'}),
        (r'PostgreSQL.*?([\d\.]+)', {'product': 'PostgreSQL', 'version': r'\1'}),
        
        # Generic version pattern
        (r'([A-Za-z][A-Za-z0-9\-_]+)[/\s]+v?([\d\.]+)', {'product': r'\1', 'version': r'\2'})
    ]
    
    for pattern, result in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            product = result['product']
            version = result['version']
            
            # Replace regex groups
            if r'\1' in product:
                product = product.replace(r'\1', match.group(1))
            if r'\2' in product:
                product = product.replace(r'\2', match.group(2) if len(match.groups()) > 1 else '')
            
            if r'\1' in version:
                version = version.replace(r'\1', match.group(1))
            if r'\2' in version:
                version = version.replace(r'\2', match.group(2) if len(match.groups()) > 1 else '')
            
            return {
                'product': product.strip(),
                'version': version.strip()
            }
    
    return {'product': '', 'version': ''}


def parse_http_response(html_content: str) -> Dict[str, Any]:
    """Parse HTTP response to extract useful information"""
    result = {
        'title': '',
        'technologies': [],
        'forms': [],
        'links': [],
        'comments': [],
        'meta_info': {}
    }
    
    if not html_content:
        return result
    
    # Extract title
    title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
    if title_match:
        result['title'] = title_match.group(1).strip()[:200]  # Limit length
    
    # Extract meta information
    meta_patterns = [
        (r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']', 'generator'),
        (r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']', 'description'),
        (r'<meta[^>]*name=["\']keywords["\'][^>]*content=["\']([^"\']+)["\']', 'keywords'),
        (r'<meta[^>]*name=["\']author["\'][^>]*content=["\']([^"\']+)["\']', 'author'),
    ]
    
    for pattern, key in meta_patterns:
        matches = re.findall(pattern, html_content, re.IGNORECASE)
        if matches:
            result['meta_info'][key] = matches[0][:500]  # Limit length
    
    # Extract technologies/frameworks
    tech_patterns = [
        (r'jquery[/-]([\d\.]+)', 'jQuery'),
        (r'bootstrap[/-]([\d\.]+)', 'Bootstrap'),
        (r'angular[/-]([\d\.]+)', 'AngularJS'),
        (r'react[/-]([\d\.]+)', 'React'),
        (r'vue[/-]([\d\.]+)', 'Vue.js'),
        (r'wordpress', 'WordPress'),
        (r'drupal', 'Drupal'),
        (r'joomla', 'Joomla'),
        (r'x-powered-by:\s*([^\r\n]+)', 'Server Technology'),
    ]
    
    for pattern, tech_name in tech_patterns:
        if re.search(pattern, html_content, re.IGNORECASE):
            if tech_name not in result['technologies']:
                result['technologies'].append(tech_name)
    
    # Extract forms
    form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
    forms = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
    
    for action, form_content in forms:
        form_info = {
            'action': action,
            'method': 'GET',
            'inputs': []
        }
        
        # Extract method
        method_match = re.search(r'method=["\']([^"\']+)["\']', form_content, re.IGNORECASE)
        if method_match:
            form_info['method'] = method_match.group(1).upper()
        
        # Extract inputs
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']([^"\']+)["\'][^>]*>'
        inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
        
        for name, input_type in inputs:
            form_info['inputs'].append({
                'name': name,
                'type': input_type
            })
        
        result['forms'].append(form_info)
    
    # Extract links
    link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>'
    links = re.findall(link_pattern, html_content, re.IGNORECASE)
    result['links'] = list(set(links[:50]))  # Limit and deduplicate
    
    # Extract comments
    comment_pattern = r'<!--(.*?)-->'
    comments = re.findall(comment_pattern, html_content, re.DOTALL)
    result['comments'] = [comment.strip()[:200] for comment in comments[:10]]  # Limit
    
    return result


def parse_openapi_spec(spec_data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse OpenAPI/Swagger specification"""
    parsed_spec = {
        'version': '',
        'title': '',
        'description': '',
        'base_url': '',
        'paths': {},
        'security_schemes': {},
        'servers': []
    }
    
    if not isinstance(spec_data, dict):
        return parsed_spec
    
    # Basic info
    info = spec_data.get('info', {})
    parsed_spec['title'] = info.get('title', '')
    parsed_spec['description'] = info.get('description', '')
    parsed_spec['version'] = info.get('version', '')
    
    # OpenAPI 3.x servers
    if 'servers' in spec_data:
        for server in spec_data.get('servers', []):
            parsed_spec['servers'].append({
                'url': server.get('url', ''),
                'description': server.get('description', '')
            })
    
    # Swagger 2.x host/basePath
    elif 'host' in spec_data:
        scheme = spec_data.get('schemes', ['https'])[0]
        host = spec_data.get('host', '')
        base_path = spec_data.get('basePath', '')
        parsed_spec['base_url'] = f"{scheme}://{host}{base_path}"
    
    # Paths
    paths = spec_data.get('paths', {})
    for path, path_info in paths.items():
        if isinstance(path_info, dict):
            parsed_spec['paths'][path] = {}
            
            for method, method_info in path_info.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']:
                    parsed_spec['paths'][path][method] = {
                        'summary': method_info.get('summary', ''),
                        'description': method_info.get('description', ''),
                        'parameters': method_info.get('parameters', []),
                        'security': method_info.get('security', []),
                        'tags': method_info.get('tags', [])
                    }
    
    # Security schemes
    if 'securityDefinitions' in spec_data:  # Swagger 2.x
        parsed_spec['security_schemes'] = spec_data['securityDefinitions']
    elif 'components' in spec_data and 'securitySchemes' in spec_data['components']:  # OpenAPI 3.x
        parsed_spec['security_schemes'] = spec_data['components']['securitySchemes']
    
    return parsed_spec


def parse_swagger_spec(spec_data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse Swagger specification (alias for OpenAPI parser)"""
    return parse_openapi_spec(spec_data)


def parse_dns_response(dns_response: str) -> List[Dict[str, str]]:
    """Parse DNS query response"""
    records = []
    
    if not dns_response:
        return records
    
    # Parse different record types
    patterns = [
        (r'(\S+)\.\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)', 'A'),
        (r'(\S+)\.\s+\d+\s+IN\s+AAAA\s+([a-fA-F0-9:]+)', 'AAAA'),
        (r'(\S+)\.\s+\d+\s+IN\s+CNAME\s+(\S+)', 'CNAME'),
        (r'(\S+)\.\s+\d+\s+IN\s+MX\s+\d+\s+(\S+)', 'MX'),
        (r'(\S+)\.\s+\d+\s+IN\s+NS\s+(\S+)', 'NS'),
        (r'(\S+)\.\s+\d+\s+IN\s+TXT\s+"([^"]+)"', 'TXT'),
    ]
    
    for pattern, record_type in patterns:
        matches = re.findall(pattern, dns_response, re.IGNORECASE)
        for name, value in matches:
            records.append({
                'name': name.rstrip('.'),
                'type': record_type,
                'value': value.rstrip('.')
            })
    
    return records


def parse_ssl_certificate(cert_data: str) -> Dict[str, Any]:
    """Parse SSL certificate information"""
    cert_info = {
        'subject': {},
        'issuer': {},
        'serial_number': '',
        'not_before': '',
        'not_after': '',
        'signature_algorithm': '',
        'public_key': {},
        'extensions': []
    }
    
    if not cert_data:
        return cert_info
    
    try:
        # This is a simplified parser - in production, use proper SSL library
        
        # Extract subject
        subject_match = re.search(r'Subject: (.+)', cert_data)
        if subject_match:
            subject_str = subject_match.group(1)
            cert_info['subject'] = parse_certificate_name(subject_str)
        
        # Extract issuer
        issuer_match = re.search(r'Issuer: (.+)', cert_data)
        if issuer_match:
            issuer_str = issuer_match.group(1)
            cert_info['issuer'] = parse_certificate_name(issuer_str)
        
        # Extract serial number
        serial_match = re.search(r'Serial Number: ([a-fA-F0-9:]+)', cert_data)
        if serial_match:
            cert_info['serial_number'] = serial_match.group(1)
        
        # Extract validity dates
        not_before_match = re.search(r'Not Before: (.+)', cert_data)
        if not_before_match:
            cert_info['not_before'] = not_before_match.group(1).strip()
        
        not_after_match = re.search(r'Not After : (.+)', cert_data)
        if not_after_match:
            cert_info['not_after'] = not_after_match.group(1).strip()
    
    except Exception:
        pass
    
    return cert_info


def parse_certificate_name(name_string: str) -> Dict[str, str]:
    """Parse certificate subject/issuer name"""
    components = {}
    
    if not name_string:
        return components
    
    # Split by commas and parse key=value pairs
    parts = name_string.split(', ')
    
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            components[key.strip()] = value.strip()
    
    return components


def extract_technologies(headers: Dict[str, str], body: str) -> Dict[str, List[str]]:
    """Extract technologies from HTTP headers and body"""
    technologies = {
        'servers': [],
        'frameworks': [],
        'cms': [],
        'languages': [],
        'other': []
    }
    
    # Server header analysis
    server = headers.get('Server', '').lower()
    if server:
        if 'nginx' in server:
            technologies['servers'].append('Nginx')
        if 'apache' in server:
            technologies['servers'].append('Apache')
        if 'iis' in server:
            technologies['servers'].append('IIS')
        if 'cloudflare' in server:
            technologies['other'].append('Cloudflare')
    
    # X-Powered-By header
    powered_by = headers.get('X-Powered-By', '').lower()
    if powered_by:
        if 'php' in powered_by:
            technologies['languages'].append('PHP')
        if 'asp.net' in powered_by:
            technologies['frameworks'].append('ASP.NET')
        if 'express' in powered_by:
            technologies['frameworks'].append('Express.js')
    
    # Content-Type analysis
    content_type = headers.get('Content-Type', '').lower()
    if 'application/json' in content_type:
        technologies['other'].append('JSON API')
    elif 'application/xml' in content_type:
        technologies['other'].append('XML API')
    
    # Body analysis
    if body:
        body_lower = body.lower()
        
        # CMS Detection
        if 'wp-content' in body_lower or 'wordpress' in body_lower:
            technologies['cms'].append('WordPress')
        if '/sites/all/modules' in body_lower or 'drupal' in body_lower:
            technologies['cms'].append('Drupal')
        if 'joomla' in body_lower:
            technologies['cms'].append('Joomla')
        
        # Framework detection
        if 'ng-' in body or 'angular' in body_lower:
            technologies['frameworks'].append('AngularJS')
        if 'react' in body_lower:
            technologies['frameworks'].append('React')
        if 'vue.js' in body_lower or '__vue__' in body:
            technologies['frameworks'].append('Vue.js')
        
        # JavaScript libraries
        if 'jquery' in body_lower:
            technologies['other'].append('jQuery')
        if 'bootstrap' in body_lower:
            technologies['other'].append('Bootstrap')
    
    # Clean up duplicates
    for category in technologies:
        technologies[category] = list(set(technologies[category]))
    
    return technologies


def parse_robots_txt(robots_content: str) -> Dict[str, List[str]]:
    """Parse robots.txt file"""
    result = {
        'disallow': [],
        'allow': [],
        'sitemap': [],
        'user_agents': []
    }
    
    if not robots_content:
        return result
    
    lines = robots_content.split('\n')
    current_user_agent = '*'
    
    for line in lines:
        line = line.strip()
        
        if not line or line.startswith('#'):
            continue
        
        if line.lower().startswith('user-agent:'):
            current_user_agent = line.split(':', 1)[1].strip()
            if current_user_agent not in result['user_agents']:
                result['user_agents'].append(current_user_agent)
        
        elif line.lower().startswith('disallow:'):
            path = line.split(':', 1)[1].strip()
            if path and path not in result['disallow']:
                result['disallow'].append(path)
        
        elif line.lower().startswith('allow:'):
            path = line.split(':', 1)[1].strip()
            if path and path not in result['allow']:
                result['allow'].append(path)
        
        elif line.lower().startswith('sitemap:'):
            sitemap_url = line.split(':', 1)[1].strip()
            if sitemap_url and sitemap_url not in result['sitemap']:
                result['sitemap'].append(sitemap_url)
    
    return result


def parse_json_response(response_text: str) -> Optional[Dict[str, Any]]:
    """Parse JSON response with error handling"""
    if not response_text:
        return None
    
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        # Try to extract JSON from HTML or other content
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass
    
    return None


def extract_urls_from_text(text: str) -> List[str]:
    """Extract URLs from text content"""
    url_pattern = re.compile(
        r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
        re.IGNORECASE
    )
    
    urls = url_pattern.findall(text)
    return list(set(urls))  # Remove duplicates


def parse_error_page(html_content: str) -> Dict[str, str]:
    """Parse error page to extract useful information"""
    error_info = {
        'server': '',
        'error_type': '',
        'version': '',
        'path': '',
        'additional_info': ''
    }
    
    if not html_content:
        return error_info
    
    # Common error page patterns
    patterns = [
        (r'Apache/(\d+\.\d+\.\d+)', 'server', 'Apache'),
        (r'nginx/(\d+\.\d+\.\d+)', 'server', 'nginx'),
        (r'Microsoft-IIS/(\d+\.\d+)', 'server', 'IIS'),
        (r'PHP/(\d+\.\d+\.\d+)', 'language', 'PHP'),
        (r'Python/(\d+\.\d+\.\d+)', 'language', 'Python'),
        (r'404 Not Found', 'error_type', '404'),
        (r'403 Forbidden', 'error_type', '403'),
        (r'500 Internal Server Error', 'error_type', '500'),
    ]
    
    for pattern, info_type, name in patterns:
        match = re.search(pattern, html_content, re.IGNORECASE)
        if match:
            if info_type == 'server':
                error_info['server'] = name
                error_info['version'] = match.group(1)
            elif info_type == 'error_type':
                error_info['error_type'] = name
    
    return error_info


def decode_base64_if_valid(data: str) -> str:
    """Decode base64 data if valid, otherwise return original"""
    try:
        if len(data) % 4 == 0 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', data):
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            return decoded
    except:
        pass
    
    return data

