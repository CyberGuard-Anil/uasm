"""
Network Scanner Module for UASM
Handles network reconnaissance including port scanning, service detection, and OS fingerprinting
"""

import subprocess
import socket
import threading
import time
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

from uasm.core.logger import create_module_logger, log_vulnerability_found, log_finding
from uasm.utils.helpers import is_valid_ip, resolve_domain
from uasm.utils.validators import validate_ip_address, validate_port
from uasm.utils.parsers import parse_nmap_xml, parse_service_banner


class NetworkScanner:
    """Network scanner for discovering hosts, ports, and services"""
    
    def __init__(self, config, target: str, database=None):
        """Initialize network scanner"""
        self.config = config
        self.target = target
        self.db = database
        self.logger = create_module_logger('NetworkScanner')
        
        # Network scanner configuration
        self.net_config = self.config.get_section('network_scanner')
        self.threads = self.net_config.get('threads', 50)
        self.timeout = self.net_config.get('timeout', 30)
        self.nmap_args = self.net_config.get('nmap_args', '-sS -sV -O')
        self.top_ports = self.net_config.get('top_ports', 1000)
        
        # Scan results
        self.results = {
            'hosts': [],
            'vulnerabilities': [],
            'findings': [],
            'statistics': {}
        }
        
        # Control flags
        self.running = False
        self._stop_event = threading.Event()
        
        self.logger.info(f"Network scanner initialized for target: {target}")
    
    def run(self) -> Dict[str, Any]:
        """Run network reconnaissance"""
        self.running = True
        self._stop_event.clear()
        
        try:
            self.logger.info("🔍 Starting network reconnaissance...")
            
            start_time = time.time()
            
            # Determine scan targets
            targets = self._prepare_targets()
            
            if not targets:
                self.logger.warning("No valid targets found for scanning")
                return self.results
            
            # Run host discovery
            live_hosts = self._discover_hosts(targets)
            
            if live_hosts:
                # Run port scanning
                self._scan_ports(live_hosts)
                
                # Service detection and OS fingerprinting
                self._detect_services_and_os()
                
                # Vulnerability assessment
                self._assess_vulnerabilities()
            
            # Calculate statistics
            self._calculate_statistics()
            
            duration = time.time() - start_time
            self.logger.info(f"✅ Network scan completed in {duration:.2f} seconds")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Network scan failed: {str(e)}")
            raise
        finally:
            self.running = False
    
    def _prepare_targets(self) -> List[str]:
        """Prepare list of targets to scan"""
        targets = []
        
        if '/' in self.target:  # CIDR notation
            # Parse CIDR range
            import ipaddress
            try:
                network = ipaddress.ip_network(self.target, strict=False)
                # Limit to reasonable size
                if network.num_addresses > 1024:
                    self.logger.warning(f"Large network detected ({network.num_addresses} hosts). Limiting scan.")
                    # Take first 256 hosts
                    targets = [str(ip) for ip in list(network.hosts())[:256]]
                else:
                    targets = [str(ip) for ip in network.hosts()]
            except ValueError as e:
                self.logger.error(f"Invalid CIDR notation: {e}")
        
        elif is_valid_ip(self.target):
            targets = [self.target]
        
        else:  # Domain name
            # Resolve domain to IP
            resolved_ip = resolve_domain(self.target)
            if resolved_ip:
                targets = [resolved_ip]
            else:
                self.logger.error(f"Failed to resolve domain: {self.target}")
        
        self.logger.info(f"Prepared {len(targets)} targets for scanning")
        return targets
    
    def _discover_hosts(self, targets: List[str]) -> List[str]:
        """Discover live hosts using ping sweeps"""
        self.logger.info("🔍 Discovering live hosts...")
        
        live_hosts = []
        
        # Use threading for host discovery
        with ThreadPoolExecutor(max_workers=min(self.threads, 50)) as executor:
            future_to_host = {
                executor.submit(self._ping_host, host): host 
                for host in targets
            }
            
            for future in as_completed(future_to_host):
                if self._stop_event.is_set():
                    break
                    
                host = future_to_host[future]
                try:
                    if future.result():
                        live_hosts.append(host)
                        self.logger.debug(f"Host {host} is alive")
                except Exception as e:
                    self.logger.debug(f"Error pinging {host}: {str(e)}")
        
        self.logger.info(f"✅ Discovered {len(live_hosts)} live hosts")
        
        # Add findings for discovered hosts
        for host in live_hosts:
            self._add_finding(
                category='network',
                subcategory='host_discovery',
                title=f'Live Host Discovered: {host}',
                description=f'Host {host} responded to ping probes',
                severity='info',
                target=host
            )
        
        return live_hosts
    
    def _ping_host(self, host: str) -> bool:
        """Ping a single host to check if it's alive"""
        try:
            # Try TCP connect to common ports first (faster than ICMP)
            common_ports = [80, 443, 22, 21, 25, 53, 110, 995, 993, 143]
            
            for port in common_ports[:3]:  # Check first 3 ports
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    
                    if result == 0:
                        return True
                except:
                    continue
            
            # Fallback to ICMP ping
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            
            return result.returncode == 0
            
        except Exception:
            return False
    
    def _scan_ports(self, hosts: List[str]):
        """Scan ports on discovered hosts"""
        self.logger.info("🔍 Scanning ports on discovered hosts...")
        
        for host in hosts:
            if self._stop_event.is_set():
                break
                
            try:
                host_data = self._scan_host_ports(host)
                if host_data:
                    self.results['hosts'].append(host_data)
                    
                    # Log findings
                    open_ports = [p for p in host_data.get('ports', []) if p.get('state') == 'open']
                    if open_ports:
                        self._add_finding(
                            category='network',
                            subcategory='port_discovery',
                            title=f'Open Ports Found on {host}',
                            description=f'Found {len(open_ports)} open ports',
                            severity='info',
                            target=host
                        )
            
            except Exception as e:
                self.logger.error(f"Error scanning {host}: {str(e)}")
    
    def _scan_host_ports(self, host: str) -> Optional[Dict[str, Any]]:
        """Scan ports on a single host"""
        self.logger.debug(f"Scanning ports on {host}")
        
        host_data = {
            'ip_address': host,
            'hostname': self._get_hostname(host),
            'status': 'up',
            'ports': [],
            'os_info': {},
            'scan_time': time.time()
        }
        
        # Define ports to scan
        if self.top_ports == 'all':
            ports = range(1, 65536)
        else:
            # Use common ports
            common_ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
                1723, 3306, 3389, 5432, 5900, 6000, 6001, 8000, 8001, 8008, 8080, 8443, 8888
            ]
            ports = common_ports[:min(len(common_ports), int(self.top_ports) if isinstance(self.top_ports, int) else 50)]
        
        # Scan ports using threading
        with ThreadPoolExecutor(max_workers=min(self.threads, 100)) as executor:
            future_to_port = {
                executor.submit(self._scan_port, host, port): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                if self._stop_event.is_set():
                    break
                    
                port = future_to_port[future]
                try:
                    port_data = future.result()
                    if port_data:
                        host_data['ports'].append(port_data)
                except Exception as e:
                    self.logger.debug(f"Error scanning port {port} on {host}: {str(e)}")
        
        # Sort ports by port number
        host_data['ports'].sort(key=lambda x: x.get('port', 0))
        
        return host_data if host_data['ports'] else None
    
    def _scan_port(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                # Port is open, try to grab banner
                banner = self._grab_banner(sock, port)
                sock.close()
                
                port_data = {
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': self._identify_service(port, banner),
                    'banner': banner[:200] if banner else '',  # Limit banner length
                    'product': '',
                    'version': ''
                }
                
                # Parse banner for product/version info
                if banner:
                    banner_info = parse_service_banner(banner)
                    port_data.update(banner_info)
                
                return port_data
            else:
                sock.close()
                return None
                
        except Exception as e:
            self.logger.debug(f"Error scanning {host}:{port} - {str(e)}")
            return None
    
    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            # Send appropriate probes based on port
            if port == 21:  # FTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port == 22:  # SSH
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port == 25:  # SMTP
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port in [80, 8080, 8000, 8443]:  # HTTP
                sock.send(b'GET / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port == 443:  # HTTPS
                # Basic banner grab (without SSL)
                try:
                    sock.send(b'GET / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    banner = "HTTPS/SSL"
            else:
                # Generic probe
                try:
                    sock.send(b'\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                except:
                    banner = ""
            
            return banner.strip()
            
        except Exception as e:
            self.logger.debug(f"Banner grab failed for port {port}: {str(e)}")
            return ""
    
    def _identify_service(self, port: int, banner: str = "") -> str:
        """Identify service based on port and banner"""
        # Common port-to-service mappings
        port_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 993: 'imaps',
            995: 'pop3s', 1723: 'pptp', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 8080: 'http-proxy'
        }
        
        # First try port-based identification
        service = port_services.get(port, f'unknown-{port}')
        
        # Refine based on banner if available
        if banner:
            banner_lower = banner.lower()
            if 'http' in banner_lower:
                service = 'https' if port == 443 else 'http'
            elif 'ftp' in banner_lower:
                service = 'ftp'
            elif 'ssh' in banner_lower:
                service = 'ssh'
            elif 'smtp' in banner_lower:
                service = 'smtp'
            elif 'mysql' in banner_lower:
                service = 'mysql'
            elif 'postgresql' in banner_lower:
                service = 'postgresql'
        
        return service
    
    def _get_hostname(self, ip: str) -> str:
        """Get hostname for IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return ip
    
    def _detect_services_and_os(self):
        """Enhanced service detection and OS fingerprinting"""
        self.logger.info("🔍 Performing service detection and OS fingerprinting...")
        
        for host_data in self.results['hosts']:
            ip = host_data.get('ip_address')
            
            # Enhanced service detection
            for port_data in host_data.get('ports', []):
                if port_data.get('state') == 'open':
                    service = port_data.get('service')
                    
                    # Add service-specific findings
                    self._add_finding(
                        category='network',
                        subcategory='service_discovery',
                        title=f'{service.upper()} Service Detected',
                        description=f'{service} service found on {ip}:{port_data["port"]}',
                        severity='info',
                        target=f"{ip}:{port_data['port']}"
                    )
                    
                    # Check for potentially dangerous services
                    dangerous_services = ['telnet', 'ftp', 'rsh', 'rlogin']
                    if service in dangerous_services:
                        self._add_vulnerability(
                            title=f'Insecure Service: {service.upper()}',
                            description=f'Potentially insecure service {service} detected',
                            severity='medium',
                            cvss_score=5.0,
                            target_host=ip,
                            target_port=port_data['port'],
                            remediation=f'Consider disabling {service} and using secure alternatives'
                        )
    
    def _assess_vulnerabilities(self):
        """Assess potential vulnerabilities based on scan results"""
        self.logger.info("🔍 Assessing potential vulnerabilities...")
        
        for host_data in self.results['hosts']:
            ip = host_data.get('ip_address')
            open_ports = [p for p in host_data.get('ports', []) if p.get('state') == 'open']
            
            # Check for excessive open ports
            if len(open_ports) > 10:
                self._add_vulnerability(
                    title='Excessive Open Ports',
                    description=f'Host has {len(open_ports)} open ports, indicating large attack surface',
                    severity='low',
                    cvss_score=3.0,
                    target_host=ip,
                    remediation='Review and close unnecessary services'
                )
            
            # Check for specific vulnerable configurations
            for port_data in open_ports:
                port = port_data.get('port')
                service = port_data.get('service')
                banner = port_data.get('banner', '')
                
                # Check for default/weak configurations
                if port == 21 and 'anonymous' in banner.lower():
                    self._add_vulnerability(
                        title='Anonymous FTP Access',
                        description='FTP server allows anonymous access',
                        severity='medium',
                        cvss_score=5.0,
                        target_host=ip,
                        target_port=port,
                        remediation='Disable anonymous FTP access'
                    )
                
                if port == 23:  # Telnet
                    self._add_vulnerability(
                        title='Insecure Telnet Service',
                        description='Telnet service transmits data in clear text',
                        severity='high',
                        cvss_score=7.5,
                        target_host=ip,
                        target_port=port,
                        remediation='Replace Telnet with SSH'
                    )
                
                # Check for outdated software versions
                if 'openssh' in banner.lower() and any(old_ver in banner.lower() for old_ver in ['5.', '6.0', '6.1']):
                    self._add_vulnerability(
                        title='Outdated SSH Version',
                        description='SSH server appears to be running an outdated version',
                        severity='medium',
                        cvss_score=5.3,
                        target_host=ip,
                        target_port=port,
                        remediation='Update SSH server to the latest version'
                    )
    
    def _calculate_statistics(self):
        """Calculate scan statistics"""
        total_hosts = len(self.results['hosts'])
        total_open_ports = sum(len([p for p in host.get('ports', []) if p.get('state') == 'open']) 
                              for host in self.results['hosts'])
        
        # Service distribution
        service_counts = {}
        for host in self.results['hosts']:
            for port in host.get('ports', []):
                if port.get('state') == 'open':
                    service = port.get('service', 'unknown')
                    service_counts[service] = service_counts.get(service, 0) + 1
        
        self.results['statistics'] = {
            'total_hosts_scanned': total_hosts,
            'total_open_ports': total_open_ports,
            'average_ports_per_host': total_open_ports / total_hosts if total_hosts > 0 else 0,
            'service_distribution': service_counts,
            'vulnerabilities_found': len(self.results['vulnerabilities']),
            'findings_count': len(self.results['findings'])
        }
    
    def _add_vulnerability(self, title: str, description: str, severity: str,
                          cvss_score: float, target_host: str, 
                          target_port: Optional[int] = None, 
                          remediation: str = "", cve_id: str = "", cwe_id: str = ""):
        """Add vulnerability to results"""
        vuln = {
            'title': title,
            'description': description,
            'severity': severity,
            'cvss_score': cvss_score,
            'target_host': target_host,
            'target_port': target_port,
            'remediation': remediation,
            'cve_id': cve_id,
            'cwe_id': cwe_id,
            'module': 'network',
            'discovered_at': time.time()
        }
        
        self.results['vulnerabilities'].append(vuln)
        log_vulnerability_found(self.logger, title, severity, target_host)
    
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
            'module': 'network',
            'discovered_at': time.time()
        }
        
        self.results['findings'].append(finding)
        log_finding(self.logger, category, title, target)
    
    def stop(self):
        """Stop the network scan"""
        self.logger.info("🛑 Stopping network scan...")
        self._stop_event.set()
        self.running = False

