"""
Web Reconnaissance Module for UASM
Handles subdomain enumeration, directory bruteforcing, and web technology detection
"""

import requests
import threading
import time
import ssl
import socket
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver

from uasm.core.logger import create_module_logger, log_vulnerability_found, log_finding
from uasm.utils.helpers import generate_user_agent, is_valid_domain, resolve_domain, clean_domain
from uasm.utils.validators import validate_url
from uasm.utils.parsers import parse_http_response, extract_technologies


class WebRecon:
    """Web reconnaissance scanner for subdomain enumeration and web analysis"""
    
    def __init__(self, config, target: str, database=None):
        """Initialize web reconnaissance scanner"""
        self.config = config
        self.target = clean_domain(target)
        self.db = database
        self.logger = create_module_logger('WebRecon')
        
        # Web recon configuration
        self.web_config = self.config.get_section('web_recon')
        self.threads = self.web_config.get('threads', 20)
        self.timeout = self.web_config.get('timeout', 30)
        self.max_redirects = self.web_config.get('max_redirects', 5)
        self.user_agents = self.web_config.get('user_agents', [generate_user_agent()])
        
        # Session for HTTP requests
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agents[0]})
        self.session.max_redirects = self.max_redirects
        
        # Scan results
        self.results = {
            'subdomains': [],
            'directories': [],
            'vulnerabilities': [],
            'findings': [],
            'technologies': [],
            'statistics': {}
        }
        
        # Control flags
        self.running = False
        self._stop_event = threading.Event()
        
        # Discovered subdomains
        self.discovered_subdomains: Set[str] = set()
        
        self.logger.info(f"Web reconnaissance initialized for target: {self.target}")
    
    def run(self) -> Dict[str, Any]:
        """Run web reconnaissance"""
        self.running = True
        self._stop_event.clear()
        
        try:
            self.logger.info("🔍 Starting web reconnaissance...")
            
            start_time = time.time()
            
            # Subdomain enumeration
            subdomains = self._enumerate_subdomains()
            
            if subdomains:
                # Analyze discovered subdomains
                self._analyze_subdomains(subdomains)
                
                # Directory bruteforcing on main subdomains
                main_subdomains = self._select_main_subdomains(subdomains)
                self._bruteforce_directories(main_subdomains)
                
                # Technology detection
                self._detect_technologies()
                
                # Web vulnerability assessment
                self._assess_web_vulnerabilities()
            
            # Calculate statistics
            self._calculate_statistics()
            
            duration = time.time() - start_time
            self.logger.info(f"✅ Web reconnaissance completed in {duration:.2f} seconds")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Web reconnaissance failed: {str(e)}")
            raise
        finally:
            self.running = False
    
    def _enumerate_subdomains(self) -> List[str]:
        """Enumerate subdomains using various techniques"""
        self.logger.info("🔍 Enumerating subdomains...")
        
        subdomains = set()
        
        # DNS bruteforcing
        if self.web_config.get('dns_bruteforce', True):
            dns_subdomains = self._dns_bruteforce()
            subdomains.update(dns_subdomains)
        
        # Certificate transparency
        if self.web_config.get('certificate_transparency', True):
            ct_subdomains = self._certificate_transparency()
            subdomains.update(ct_subdomains)
        
        # Search engine dorking (if enabled)
        if self.web_config.get('search_engine_dorking', False):
            search_subdomains = self._search_engine_dorking()
            subdomains.update(search_subdomains)
        
        # Zone transfer attempt
        zone_subdomains = self._attempt_zone_transfer()
        subdomains.update(zone_subdomains)
        
        # Remove invalid subdomains
        valid_subdomains = [sub for sub in subdomains if is_valid_domain(sub)]
        
        self.logger.info(f"✅ Discovered {len(valid_subdomains)} subdomains")
        
        return valid_subdomains
    
    def _dns_bruteforce(self) -> List[str]:
        """Bruteforce subdomains using DNS queries"""
        self.logger.debug("Running DNS bruteforce...")
        
        # Default subdomain wordlist
        common_subdomains = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'admin', 'api', 'cdn', 'ftp', 'test',
            'portal', 'host', 'mobile', 'exchange', 'owa', 'www2', 'gw', 'email',
            'support', 'chat', 'wap', 'pda', 'mail2', 'tv', 'secure2', 'proxy',
            'wap2', 'shop', 'beta', 'news', 'video', 'web', 'ftp2', 'promo',
            'staging', 'dev', 'development', 'prod', 'production', 'demo',
            'backup', 'old', 'new', 'app', 'apps', 'service', 'services',
            'help', 'helpdesk', 'support', 'docs', 'documentation', 'wiki'
        ]
        
        discovered = []
        
        with ThreadPoolExecutor(max_workers=min(self.threads, 50)) as executor:
            future_to_subdomain = {
                executor.submit(self._resolve_subdomain, subdomain): subdomain
                for subdomain in common_subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                if self._stop_event.is_set():
                    break
                
                subdomain = future_to_subdomain[future]
                try:
                    result = future.result()
                    if result:
                        full_subdomain = f"{subdomain}.{self.target}"
                        discovered.append(full_subdomain)
                        self.discovered_subdomains.add(full_subdomain)
                        
                        self._add_finding(
                            category='web',
                            subcategory='subdomain_discovery',
                            title=f'Subdomain Found: {full_subdomain}',
                            description=f'Subdomain discovered via DNS bruteforce',
                            severity='info',
                            target=full_subdomain
                        )
                        
                except Exception as e:
                    self.logger.debug(f"Error resolving {subdomain}: {str(e)}")
        
        return discovered
    
    def _resolve_subdomain(self, subdomain: str) -> Optional[str]:
        """Resolve a subdomain to check if it exists"""
        try:
            full_subdomain = f"{subdomain}.{self.target}"
            result = dns.resolver.resolve(full_subdomain, 'A')
            if result:
                return str(result[0])
        except:
            pass
        
        return None
    
    def _certificate_transparency(self) -> List[str]:
        """Search Certificate Transparency logs for subdomains"""
        self.logger.debug("Searching Certificate Transparency logs...")
        
        discovered = []
        
        try:
            # Query crt.sh (Certificate Transparency search)
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    if name_value:
                        # Extract subdomains from certificate
                        domains = name_value.split('\n')
                        for domain in domains:
                            domain = domain.strip()
                            if domain.endswith(f'.{self.target}') and domain not in discovered:
                                discovered.append(domain)
                                self.discovered_subdomains.add(domain)
                                
                                self._add_finding(
                                    category='web',
                                    subcategory='subdomain_discovery',
                                    title=f'Subdomain Found: {domain}',
                                    description='Subdomain discovered via Certificate Transparency logs',
                                    severity='info',
                                    target=domain
                                )
        
        except Exception as e:
            self.logger.debug(f"Certificate transparency search failed: {str(e)}")
        
        return discovered
    
    def _search_engine_dorking(self) -> List[str]:
        """Search engine dorking for subdomain discovery"""
        # Placeholder for search engine dorking
        # In production, this would query search engines with site: operators
        self.logger.debug("Search engine dorking disabled by default")
        return []
    
    def _attempt_zone_transfer(self) -> List[str]:
        """Attempt DNS zone transfer"""
        self.logger.debug("Attempting DNS zone transfer...")
        
        discovered = []
        
        try:
            # Get NS records for the domain
            ns_records = dns.resolver.resolve(self.target, 'NS')
            
            for ns in ns_records:
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), self.target))
                    
                    for name, node in zone.nodes.items():
                        if name != '@':
                            subdomain = f"{name}.{self.target}"
                            discovered.append(subdomain)
                            
                            self._add_vulnerability(
                                title='DNS Zone Transfer Enabled',
                                description=f'Zone transfer allowed from {ns}',
                                severity='medium',
                                cvss_score=5.0,
                                target_url=f'dns://{ns}',
                                remediation='Disable zone transfers for unauthorized hosts'
                            )
                            
                except Exception:
                    # Zone transfer failed (which is normal)
                    continue
                    
        except Exception as e:
            self.logger.debug(f"Zone transfer attempt failed: {str(e)}")
        
        return discovered
    
    def _analyze_subdomains(self, subdomains: List[str]):
        """Analyze discovered subdomains"""
        self.logger.info(f"🔍 Analyzing {len(subdomains)} discovered subdomains...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self._analyze_subdomain, subdomain): subdomain
                for subdomain in subdomains
            }
            
            for future in as_completed(future_to_subdomain):
                if self._stop_event.is_set():
                    break
                
                subdomain = future_to_subdomain[future]
                try:
                    subdomain_data = future.result()
                    if subdomain_data:
                        self.results['subdomains'].append(subdomain_data)
                        
                except Exception as e:
                    self.logger.debug(f"Error analyzing {subdomain}: {str(e)}")
    
    def _analyze_subdomain(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """Analyze a single subdomain"""
        subdomain_data = {
            'subdomain': subdomain,
            'ip_address': resolve_domain(subdomain),
            'status_code': None,
            'title': '',
            'server': '',
            'technologies': [],
            'ssl_info': {},
            'interesting_paths': [],
            'response_time': 0
        }
        
        # Test HTTP and HTTPS
        protocols = ['https', 'http']
        
        for protocol in protocols:
            url = f"{protocol}://{subdomain}"
            
            try:
                start_time = time.time()
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                response_time = time.time() - start_time
                
                subdomain_data['status_code'] = response.status_code
                subdomain_data['response_time'] = response_time
                subdomain_data['url'] = url
                
                # Extract server header
                subdomain_data['server'] = response.headers.get('Server', '')
                
                # Extract title and analyze content
                if response.text:
                    parsed_content = parse_http_response(response.text)
                    subdomain_data['title'] = parsed_content.get('title', '')
                    subdomain_data['technologies'] = parsed_content.get('technologies', [])
                
                # SSL/TLS analysis for HTTPS
                if protocol == 'https':
                    ssl_info = self._analyze_ssl(subdomain)
                    if ssl_info:
                        subdomain_data['ssl_info'] = ssl_info
                
                # WAF detection
                waf_detected = self._detect_waf(response)
                if waf_detected:
                    subdomain_data['waf'] = waf_detected
                    
                    self._add_finding(
                        category='web',
                        subcategory='waf_detection',
                        title=f'WAF Detected: {waf_detected}',
                        description=f'Web Application Firewall detected on {subdomain}',
                        severity='info',
                        target=subdomain
                    )
                
                break  # Success, don't try other protocol
                
            except requests.exceptions.SSLError:
                # SSL error, try HTTP
                continue
            except requests.exceptions.RequestException as e:
                self.logger.debug(f"Request to {url} failed: {str(e)}")
                continue
        
        return subdomain_data if subdomain_data['status_code'] else None
    
    def _analyze_ssl(self, hostname: str) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher()[0] if ssock.cipher() else '',
                        'subject': dict(x for x in cert.get('subject', [])),
                        'issuer': dict(x for x in cert.get('issuer', [])),
                        'not_before': cert.get('notBefore', ''),
                        'not_after': cert.get('notAfter', ''),
                        'serial_number': cert.get('serialNumber', ''),
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    # Check for weak configurations
                    if ssock.version() in ['TLSv1', 'TLSv1.1']:
                        self._add_vulnerability(
                            title='Weak TLS Version',
                            description=f'Server supports weak TLS version: {ssock.version()}',
                            severity='medium',
                            cvss_score=5.0,
                            target_url=f'https://{hostname}',
                            remediation='Disable TLS 1.0 and 1.1, use TLS 1.2 or higher'
                        )
        
        except Exception as e:
            self.logger.debug(f"SSL analysis failed for {hostname}: {str(e)}")
        
        return ssl_info
    
    def _detect_waf(self, response: requests.Response) -> Optional[str]:
        """Detect Web Application Firewall"""
        # WAF detection based on headers and response patterns
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray'],
            'AWS WAF': ['x-amzn-requestid'],
            'Akamai': ['akamai'],
            'Incapsula': ['x-iinfo'],
            'ModSecurity': ['mod_security'],
            'Barracuda': ['barra'],
            'F5 BIG-IP': ['bigip', 'f5'],
            'Fortinet': ['fortigate']
        }
        
        response_text = response.text.lower()
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for waf_name, signatures in waf_signatures.items():
            for signature in signatures:
                if (signature in response_text or 
                    any(signature in header_value for header_value in headers.values())):
                    return waf_name
        
        return None
    
    def _select_main_subdomains(self, subdomains: List[str]) -> List[str]:
        """Select main subdomains for detailed analysis"""
        # Prioritize common subdomains
        priority_subdomains = []
        common_names = ['www', 'api', 'app', 'admin', 'portal', 'mail', 'blog']
        
        for subdomain in subdomains:
            subdomain_name = subdomain.split('.')[0]
            if subdomain_name in common_names:
                priority_subdomains.append(subdomain)
        
        # Add random subdomains if we have room
        remaining = [s for s in subdomains if s not in priority_subdomains]
        priority_subdomains.extend(remaining[:max(0, 10 - len(priority_subdomains))])
        
        return priority_subdomains[:10]  # Limit to 10 subdomains
    
    def _bruteforce_directories(self, subdomains: List[str]):
        """Bruteforce directories on selected subdomains"""
        self.logger.info("🔍 Bruteforcing directories...")
        
        # Common directory wordlist
        common_directories = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'backups', 'api', 'v1', 'v2', 'test', 'dev', 'staging',
            'uploads', 'images', 'files', 'download', 'downloads', 'doc', 'docs',
            'config', 'configuration', 'setup', 'install', 'installer',
            'panel', 'cpanel', 'webmail', 'mail', 'email', 'support', 'help',
            'old', 'new', 'tmp', 'temp', 'cache', 'assets', 'static', 'js', 'css'
        ]
        
        for subdomain in subdomains[:3]:  # Limit to first 3 subdomains
            if self._stop_event.is_set():
                break
                
            self._bruteforce_subdomain_directories(subdomain, common_directories)
    
    def _bruteforce_subdomain_directories(self, subdomain: str, directories: List[str]):
        """Bruteforce directories on a single subdomain"""
        base_url = f"https://{subdomain}"
        
        # Test if HTTPS works, fallback to HTTP
        try:
            response = self.session.head(base_url, timeout=5)
        except:
            base_url = f"http://{subdomain}"
        
        interesting_dirs = []
        
        with ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
            future_to_dir = {
                executor.submit(self._test_directory, base_url, directory): directory
                for directory in directories
            }
            
            for future in as_completed(future_to_dir):
                if self._stop_event.is_set():
                    break
                
                directory = future_to_dir[future]
                try:
                    result = future.result()
                    if result:
                        interesting_dirs.append(result)
                        
                        self._add_finding(
                            category='web',
                            subcategory='directory_discovery',
                            title=f'Directory Found: {result["path"]}',
                            description=f'Accessible directory discovered on {subdomain}',
                            severity='info',
                            target=result['url']
                        )
                        
                        # Check for sensitive directories
                        if directory in ['admin', 'administrator', 'config', 'backup']:
                            self._add_vulnerability(
                                title=f'Sensitive Directory Accessible: {directory}',
                                description=f'Potentially sensitive directory {directory} is accessible',
                                severity='medium',
                                cvss_score=4.0,
                                target_url=result['url'],
                                remediation='Restrict access to sensitive directories'
                            )
                            
                except Exception as e:
                    self.logger.debug(f"Error testing directory {directory}: {str(e)}")
        
        if interesting_dirs:
            self.results['directories'].extend(interesting_dirs)
    
    def _test_directory(self, base_url: str, directory: str) -> Optional[Dict[str, Any]]:
        """Test if a directory exists and is accessible"""
        url = urljoin(base_url, directory + '/')
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Consider it found if status is 200, 403, or 401
            if response.status_code in [200, 401, 403]:
                return {
                    'path': directory,
                    'url': url,
                    'status_code': response.status_code,
                    'size': len(response.content),
                    'title': parse_http_response(response.text).get('title', '') if response.status_code == 200 else ''
                }
        
        except Exception:
            pass
        
        return None
    
    def _detect_technologies(self):
        """Detect web technologies across discovered subdomains"""
        self.logger.info("🔍 Detecting web technologies...")
        
        all_technologies = []
        
        for subdomain_data in self.results['subdomains']:
            technologies = subdomain_data.get('technologies', [])
            server = subdomain_data.get('server', '')
            
            if server:
                # Parse server header for technology info
                server_tech = extract_technologies({'Server': server}, '')
                technologies.extend(server_tech.get('other', []))
            
            # Add to global technology list
            for tech in technologies:
                if tech not in [t['name'] for t in all_technologies]:
                    all_technologies.append({
                        'name': tech,
                        'subdomains': [subdomain_data['subdomain']],
                        'confidence': 'medium'
                    })
                else:
                    # Update existing technology
                    for existing_tech in all_technologies:
                        if existing_tech['name'] == tech:
                            if subdomain_data['subdomain'] not in existing_tech['subdomains']:
                                existing_tech['subdomains'].append(subdomain_data['subdomain'])
        
        self.results['technologies'] = all_technologies
        
        # Add findings for interesting technologies
        for tech in all_technologies:
            self._add_finding(
                category='web',
                subcategory='technology_detection',
                title=f'Technology Detected: {tech["name"]}',
                description=f'Web technology {tech["name"]} detected on {len(tech["subdomains"])} subdomain(s)',
                severity='info',
                target=', '.join(tech['subdomains'][:3])  # Limit to first 3
            )
    
    def _assess_web_vulnerabilities(self):
        """Assess web vulnerabilities"""
        self.logger.info("🔍 Assessing web vulnerabilities...")
        
        for subdomain_data in self.results['subdomains']:
            subdomain = subdomain_data['subdomain']
            
            # Check for missing security headers
            if 'url' in subdomain_data:
                self._check_security_headers(subdomain_data['url'])
            
            # Check for information disclosure
            self._check_information_disclosure(subdomain_data)
            
            # Check for common vulnerabilities based on technologies
            technologies = subdomain_data.get('technologies', [])
            for tech in technologies:
                self._check_technology_vulnerabilities(tech, subdomain)
    
    def _check_security_headers(self, url: str):
        """Check for missing security headers"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            headers = response.headers
            
            # Required security headers
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header allows clickjacking attacks',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options allows MIME sniffing',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'Strict-Transport-Security': 'Missing HSTS header allows protocol downgrade attacks',
                'Content-Security-Policy': 'Missing CSP header allows XSS and data injection'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    self._add_vulnerability(
                        title=f'Missing Security Header: {header}',
                        description=description,
                        severity='low',
                        cvss_score=2.0,
                        target_url=url,
                        remediation=f'Add {header} header to HTTP responses'
                    )
        
        except Exception as e:
            self.logger.debug(f"Error checking security headers for {url}: {str(e)}")
    
    def _check_information_disclosure(self, subdomain_data: Dict[str, Any]):
        """Check for information disclosure"""
        server = subdomain_data.get('server', '')
        subdomain = subdomain_data.get('subdomain', '')
        
        # Check for verbose server headers
        if server and any(keyword in server.lower() for keyword in ['apache', 'nginx', 'iis']):
            # Check if version is disclosed
            if any(char.isdigit() for char in server):
                self._add_vulnerability(
                    title='Server Version Disclosure',
                    description=f'Server header reveals version information: {server}',
                    severity='low',
                    cvss_score=2.0,
                    target_url=f"https://{subdomain}",
                    remediation='Configure server to hide version information'
                )
    
    def _check_technology_vulnerabilities(self, technology: str, subdomain: str):
        """Check for known vulnerabilities in detected technologies"""
        tech_lower = technology.lower()
        
        # Known vulnerable technologies (simplified)
        if 'wordpress' in tech_lower:
            self._add_finding(
                category='web',
                subcategory='cms_detection',
                title='WordPress Detected',
                description='WordPress CMS detected - ensure plugins and core are updated',
                severity='info',
                target=subdomain
            )
        
        elif 'drupal' in tech_lower:
            self._add_finding(
                category='web',
                subcategory='cms_detection',
                title='Drupal Detected',
                description='Drupal CMS detected - ensure modules and core are updated',
                severity='info',
                target=subdomain
            )
        
        elif 'joomla' in tech_lower:
            self._add_finding(
                category='web',
                subcategory='cms_detection',
                title='Joomla Detected',
                description='Joomla CMS detected - ensure extensions and core are updated',
                severity='info',
                target=subdomain
            )
    
    def _calculate_statistics(self):
        """Calculate web reconnaissance statistics"""
        self.results['statistics'] = {
            'total_subdomains': len(self.results['subdomains']),
            'total_directories': len(self.results['directories']),
            'total_technologies': len(self.results['technologies']),
            'vulnerabilities_found': len(self.results['vulnerabilities']),
            'findings_count': len(self.results['findings']),
            'ssl_enabled_subdomains': len([s for s in self.results['subdomains'] if s.get('ssl_info')]),
            'waf_protected_subdomains': len([s for s in self.results['subdomains'] if s.get('waf')])
        }
    
    def _add_vulnerability(self, title: str, description: str, severity: str,
                          cvss_score: float, target_url: str, 
                          remediation: str = "", cve_id: str = "", cwe_id: str = ""):
        """Add vulnerability to results"""
        vuln = {
            'title': title,
            'description': description,
            'severity': severity,
            'cvss_score': cvss_score,
            'target_url': target_url,
            'remediation': remediation,
            'cve_id': cve_id,
            'cwe_id': cwe_id,
            'module': 'web',
            'discovered_at': time.time()
        }
        
        self.results['vulnerabilities'].append(vuln)
        log_vulnerability_found(self.logger, title, severity, target_url)
    
    def _add_finding(self, category: str, subcategory: str, title: str, 
                    description: str, severity: str, target: str):
        """Add finding to results"""
        finding = {
            'category': category,
            'subcategory': subcategory,
            'title': title,
            'description': description,
            'severity': severity,
            'target': target,
            'module': 'web',
            'discovered_at': time.time()
        }
        
        self.results['findings'].append(finding)
        log_finding(self.logger, category, title, target)
    
    def stop(self):
        """Stop the web reconnaissance scan"""
        self.logger.info("🛑 Stopping web reconnaissance...")
        self._stop_event.set()
        self.running = False

