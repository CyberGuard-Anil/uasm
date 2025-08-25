"""
Results Correlator Module for UASM
Correlates findings across different scanner modules and generates attack paths
"""

import time
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict
import ipaddress

from uasm.core.logger import create_module_logger


class ResultsCorrelator:
    """Correlate results across scanner modules and generate insights"""
    
    def __init__(self, config):
        """Initialize results correlator"""
        self.config = config
        self.logger = create_module_logger('ResultsCorrelator')
        
        # Correlation configuration
        self.correlation_config = self.config.get('correlation', {})
        self.confidence_threshold = self.correlation_config.get('confidence_threshold', 0.7)
        
        self.logger.info("Results correlator initialized")
    
    def correlate_network_web(self, network_hosts: List[Dict], web_subdomains: List[Dict]) -> Dict[str, Any]:
        """Correlate network and web reconnaissance results"""
        self.logger.info("🔗 Correlating network and web results...")
        
        correlations = {
            'ip_subdomain_mappings': [],
            'service_web_correlations': [],
            'certificate_ip_correlations': []
        }
        
        # Map subdomains to IPs
        for subdomain in web_subdomains:
            subdomain_name = subdomain.get('subdomain', '')
            subdomain_ip = subdomain.get('ip_address', '')
            
            if subdomain_ip:
                # Find matching network host
                for host in network_hosts:
                    host_ip = host.get('ip_address', '')
                    
                    if host_ip == subdomain_ip:
                        correlation = {
                            'subdomain': subdomain_name,
                            'ip_address': subdomain_ip,
                            'hostname': host.get('hostname', ''),
                            'open_ports': [p['port'] for p in host.get('ports', []) if p.get('state') == 'open'],
                            'web_status': subdomain.get('status_code'),
                            'web_server': subdomain.get('server', ''),
                            'confidence': 1.0
                        }
                        correlations['ip_subdomain_mappings'].append(correlation)
        
        # Correlate web services with network services
        for subdomain in web_subdomains:
            subdomain_ip = subdomain.get('ip_address', '')
            web_server = subdomain.get('server', '')
            
            for host in network_hosts:
                if host.get('ip_address') == subdomain_ip:
                    for port in host.get('ports', []):
                        if port.get('state') == 'open' and port.get('service') in ['http', 'https']:
                            correlation = {
                                'subdomain': subdomain.get('subdomain', ''),
                                'ip_address': subdomain_ip,
                                'port': port.get('port'),
                                'network_service': port.get('service'),
                                'web_server': web_server,
                                'banner': port.get('banner', ''),
                                'confidence': self._calculate_service_correlation_confidence(port, subdomain)
                            }
                            correlations['service_web_correlations'].append(correlation)
        
        self.logger.info(f"✅ Found {len(correlations['ip_subdomain_mappings'])} IP-subdomain correlations")
        return correlations
    
    def find_api_endpoints(self, web_subdomains: List[Dict]) -> List[Dict[str, Any]]:
        """Find potential API endpoints from web data"""
        self.logger.info("🔗 Identifying API endpoints from web data...")
        
        api_endpoints = []
        
        # API indicators
        api_indicators = [
            'api', 'rest', 'graphql', 'swagger', 'openapi', 
            'json', 'xml', 'endpoint', 'service'
        ]
        
        for subdomain in web_subdomains:
            subdomain_name = subdomain.get('subdomain', '').lower()
            title = subdomain.get('title', '').lower()
            
            # Check subdomain name for API indicators
            api_likelihood = 0
            for indicator in api_indicators:
                if indicator in subdomain_name:
                    api_likelihood += 0.3
                if indicator in title:
                    api_likelihood += 0.2
            
            # Check for API-specific patterns
            if subdomain_name.startswith('api.'):
                api_likelihood += 0.5
            if any(pattern in subdomain_name for pattern in ['v1', 'v2', 'v3']):
                api_likelihood += 0.3
            if subdomain.get('status_code') == 401:  # Unauthorized often indicates API
                api_likelihood += 0.2
            
            if api_likelihood >= 0.5:
                api_endpoint = {
                    'subdomain': subdomain.get('subdomain'),
                    'url': f"https://{subdomain.get('subdomain')}",
                    'ip_address': subdomain.get('ip_address'),
                    'api_likelihood': min(api_likelihood, 1.0),
                    'indicators': [ind for ind in api_indicators 
                                 if ind in subdomain_name or ind in title],
                    'status_code': subdomain.get('status_code'),
                    'server': subdomain.get('server', '')
                }
                api_endpoints.append(api_endpoint)
        
        self.logger.info(f"✅ Identified {len(api_endpoints)} potential API endpoints")
        return api_endpoints
    
    def enrich_vulnerabilities(self, vulnerabilities: List[Dict], 
                             network_hosts: List[Dict], 
                             web_subdomains: List[Dict]) -> List[Dict[str, Any]]:
        """Enrich vulnerabilities with additional context"""
        self.logger.info("🔗 Enriching vulnerabilities with context...")
        
        enriched_vulnerabilities = []
        
        for vuln in vulnerabilities:
            enriched_vuln = vuln.copy()
            
            # Add network context
            target_host = vuln.get('target_host', '')
            target_url = vuln.get('target_url', '')
            
            if target_host:
                host_context = self._get_host_context(target_host, network_hosts)
                if host_context:
                    enriched_vuln['host_context'] = host_context
            
            # Add web context
            if target_url:
                web_context = self._get_web_context(target_url, web_subdomains)
                if web_context:
                    enriched_vuln['web_context'] = web_context
            
            # Calculate business impact
            enriched_vuln['business_impact'] = self._assess_business_impact(enriched_vuln)
            
            # Calculate exploitability
            enriched_vuln['exploitability'] = self._assess_exploitability(enriched_vuln)
            
            # Add related vulnerabilities
            enriched_vuln['related_vulnerabilities'] = self._find_related_vulnerabilities(
                enriched_vuln, vulnerabilities
            )
            
            enriched_vulnerabilities.append(enriched_vuln)
        
        self.logger.info(f"✅ Enriched {len(vulnerabilities)} vulnerabilities")
        return enriched_vulnerabilities
    
    def generate_attack_paths(self, network_hosts: List[Dict], 
                            web_subdomains: List[Dict], 
                            vulnerabilities: List[Dict]) -> List[Dict[str, Any]]:
        """Generate potential attack paths"""
        self.logger.info("🔗 Generating attack paths...")
        
        attack_paths = []
        
        # Group vulnerabilities by target
        vuln_by_host = defaultdict(list)
        vuln_by_subdomain = defaultdict(list)
        
        for vuln in vulnerabilities:
            if vuln.get('target_host'):
                vuln_by_host[vuln['target_host']].append(vuln)
            if vuln.get('target_url'):
                # Extract domain from URL
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(vuln['target_url']).hostname
                    if domain:
                        vuln_by_subdomain[domain].append(vuln)
                except:
                    pass
        
        # Generate attack paths from external to internal
        for subdomain in web_subdomains:
            subdomain_name = subdomain.get('subdomain', '')
            subdomain_ip = subdomain.get('ip_address', '')
            
            # Check if this subdomain has vulnerabilities
            subdomain_vulns = vuln_by_subdomain.get(subdomain_name, [])
            
            if subdomain_vulns and subdomain_ip:
                # Find network host for this IP
                network_host = None
                for host in network_hosts:
                    if host.get('ip_address') == subdomain_ip:
                        network_host = host
                        break
                
                if network_host:
                    host_vulns = vuln_by_host.get(subdomain_ip, [])
                    
                    # Create attack path
                    attack_path = {
                        'path_id': f"path_{len(attack_paths) + 1}",
                        'entry_point': {
                            'type': 'web',
                            'target': subdomain_name,
                            'ip': subdomain_ip,
                            'vulnerabilities': subdomain_vulns
                        },
                        'lateral_movement': {
                            'type': 'network',
                            'target': subdomain_ip,
                            'open_ports': [p['port'] for p in network_host.get('ports', []) 
                                         if p.get('state') == 'open'],
                            'vulnerabilities': host_vulns
                        },
                        'severity': self._calculate_path_severity(subdomain_vulns + host_vulns),
                        'complexity': self._calculate_attack_complexity(subdomain_vulns + host_vulns),
                        'steps': self._generate_attack_steps(subdomain_vulns, host_vulns)
                    }
                    
                    attack_paths.append(attack_path)
        
        # Sort by severity
        attack_paths.sort(key=lambda x: x.get('severity', 0), reverse=True)
        
        self.logger.info(f"✅ Generated {len(attack_paths)} attack paths")
        return attack_paths
    
    def prioritize_findings(self, findings: List[Dict]) -> List[Dict[str, Any]]:
        """Prioritize findings based on various factors"""
        self.logger.info("🔗 Prioritizing findings...")
        
        prioritized_findings = []
        
        for finding in findings:
            prioritized_finding = finding.copy()
            
            # Calculate priority score
            priority_score = self._calculate_finding_priority(finding)
            prioritized_finding['priority_score'] = priority_score
            
            # Assign priority level
            if priority_score >= 8.0:
                prioritized_finding['priority_level'] = 'critical'
            elif priority_score >= 6.0:
                prioritized_finding['priority_level'] = 'high'
            elif priority_score >= 4.0:
                prioritized_finding['priority_level'] = 'medium'
            else:
                prioritized_finding['priority_level'] = 'low'
            
            # Add context
            prioritized_finding['context'] = self._get_finding_context(finding)
            
            prioritized_findings.append(prioritized_finding)
        
        # Sort by priority score
        prioritized_findings.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
        
        self.logger.info(f"✅ Prioritized {len(findings)} findings")
        return prioritized_findings
    
    def _calculate_service_correlation_confidence(self, port_info: Dict, subdomain_info: Dict) -> float:
        """Calculate confidence for service correlation"""
        confidence = 0.5  # Base confidence
        
        # Port and service type match
        port = port_info.get('port', 0)
        if port in [80, 8080] and subdomain_info.get('status_code'):
            confidence += 0.3
        elif port in [443, 8443] and subdomain_info.get('url', '').startswith('https'):
            confidence += 0.3
        
        # Server header correlation
        network_banner = port_info.get('banner', '').lower()
        web_server = subdomain_info.get('server', '').lower()
        
        if network_banner and web_server:
            if any(server in network_banner for server in ['nginx', 'apache', 'iis']):
                confidence += 0.2
        
        return min(confidence, 1.0)
    
    def _get_host_context(self, target_host: str, network_hosts: List[Dict]) -> Optional[Dict]:
        """Get network context for a host"""
        for host in network_hosts:
            if host.get('ip_address') == target_host:
                return {
                    'hostname': host.get('hostname', ''),
                    'os_info': host.get('os_info', {}),
                    'open_ports': [p['port'] for p in host.get('ports', []) if p.get('state') == 'open'],
                    'services': [p['service'] for p in host.get('ports', []) if p.get('state') == 'open']
                }
        return None
    
    def _get_web_context(self, target_url: str, web_subdomains: List[Dict]) -> Optional[Dict]:
        """Get web context for a URL"""
        try:
            from urllib.parse import urlparse
            domain = urlparse(target_url).hostname
            
            for subdomain in web_subdomains:
                if subdomain.get('subdomain') == domain:
                    return {
                        'title': subdomain.get('title', ''),
                        'server': subdomain.get('server', ''),
                        'technologies': subdomain.get('technologies', []),
                        'status_code': subdomain.get('status_code'),
                        'ssl_info': subdomain.get('ssl_info', {})
                    }
        except:
            pass
        
        return None
    
    def _assess_business_impact(self, vulnerability: Dict) -> str:
        """Assess business impact of vulnerability"""
        severity = vulnerability.get('severity', '').lower()
        cvss_score = vulnerability.get('cvss_score', 0)
        
        # Base impact on severity
        if severity == 'critical' or cvss_score >= 9.0:
            return 'High - Critical system compromise possible'
        elif severity == 'high' or cvss_score >= 7.0:
            return 'Medium - Significant security impact'
        elif severity == 'medium' or cvss_score >= 4.0:
            return 'Low - Limited security impact'
        else:
            return 'Minimal - Informational finding'
    
    def _assess_exploitability(self, vulnerability: Dict) -> Dict[str, Any]:
        """Assess exploitability of vulnerability"""
        severity = vulnerability.get('severity', '').lower()
        module = vulnerability.get('module', '')
        
        # Base exploitability assessment
        if severity == 'critical':
            difficulty = 'Easy'
            time_to_exploit = 'Minutes'
        elif severity == 'high':
            difficulty = 'Moderate'
            time_to_exploit = 'Hours'
        elif severity == 'medium':
            difficulty = 'Difficult'
            time_to_exploit = 'Days'
        else:
            difficulty = 'Very Difficult'
            time_to_exploit = 'Weeks'
        
        # Adjust based on module
        if module == 'web':
            # Web vulnerabilities often easier to exploit
            if difficulty == 'Moderate':
                difficulty = 'Easy'
            elif difficulty == 'Difficult':
                difficulty = 'Moderate'
        
        return {
            'difficulty': difficulty,
            'estimated_time': time_to_exploit,
            'remote_exploitable': module in ['web', 'api'],
            'authentication_required': 'authentication' in vulnerability.get('description', '').lower()
        }
    
    def _find_related_vulnerabilities(self, target_vuln: Dict, all_vulnerabilities: List[Dict]) -> List[str]:
        """Find related vulnerabilities"""
        related = []
        target_host = target_vuln.get('target_host', '')
        target_url = target_vuln.get('target_url', '')
        
        for vuln in all_vulnerabilities:
            if vuln == target_vuln:
                continue
                
            # Same host
            if target_host and vuln.get('target_host') == target_host:
                related.append(vuln.get('title', 'Unknown'))
            
            # Same domain
            elif target_url and vuln.get('target_url'):
                try:
                    from urllib.parse import urlparse
                    target_domain = urlparse(target_url).hostname
                    vuln_domain = urlparse(vuln.get('target_url')).hostname
                    if target_domain == vuln_domain:
                        related.append(vuln.get('title', 'Unknown'))
                except:
                    pass
        
        return related[:5]  # Limit to 5 related vulns
    
    def _calculate_path_severity(self, vulnerabilities: List[Dict]) -> float:
        """Calculate attack path severity"""
        if not vulnerabilities:
            return 0.0
        
        # Use highest CVSS score
        max_cvss = max(vuln.get('cvss_score', 0) for vuln in vulnerabilities)
        return max_cvss
    
    def _calculate_attack_complexity(self, vulnerabilities: List[Dict]) -> str:
        """Calculate attack complexity"""
        if not vulnerabilities:
            return 'Unknown'
        
        # Count by severity
        critical_count = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high_count = len([v for v in vulnerabilities if v.get('severity') == 'high'])
        
        if critical_count > 0:
            return 'Low'  # Critical vulns make attack easier
        elif high_count > 1:
            return 'Medium'
        else:
            return 'High'
    
    def _generate_attack_steps(self, web_vulns: List[Dict], network_vulns: List[Dict]) -> List[Dict]:
        """Generate attack steps"""
        steps = []
        step_num = 1
        
        # Web exploitation steps
        for vuln in web_vulns:
            if vuln.get('severity') in ['critical', 'high']:
                steps.append({
                    'step': step_num,
                    'phase': 'Initial Access',
                    'action': f'Exploit {vuln.get("title", "vulnerability")}',
                    'target': vuln.get('target_url', ''),
                    'impact': 'Web application compromise'
                })
                step_num += 1
        
        # Network exploitation steps
        for vuln in network_vulns:
            if vuln.get('severity') in ['critical', 'high']:
                steps.append({
                    'step': step_num,
                    'phase': 'Lateral Movement',
                    'action': f'Exploit {vuln.get("title", "vulnerability")}',
                    'target': vuln.get('target_host', ''),
                    'impact': 'System compromise'
                })
                step_num += 1
        
        return steps
    
    def _calculate_finding_priority(self, finding: Dict) -> float:
        """Calculate priority score for finding"""
        score = 0.0
        
        # Base score from severity
        severity = finding.get('severity', 'info').lower()
        severity_scores = {
            'critical': 9.0,
            'high': 7.0,
            'medium': 5.0,
            'low': 3.0,
            'info': 1.0
        }
        score += severity_scores.get(severity, 1.0)
        
        # Module weight
        module = finding.get('module', '')
        module_weights = {
            'network': 0.8,
            'web': 1.0,
            'api': 1.2,
            'cloud': 1.1
        }
        score *= module_weights.get(module, 1.0)
        
        # Category weight
        category = finding.get('category', '').lower()
        if 'vulnerability' in category or 'exploit' in category:
            score *= 1.2
        elif 'discovery' in category:
            score *= 0.8
        
        return min(score, 10.0)
    
    def _get_finding_context(self, finding: Dict) -> Dict[str, Any]:
        """Get context information for finding"""
        return {
            'module': finding.get('module', 'unknown'),
            'category': finding.get('category', 'unknown'),
            'subcategory': finding.get('subcategory', 'unknown'),
            'discovery_time': finding.get('discovered_at', time.time()),
            'target_type': self._identify_target_type(finding.get('target', ''))
        }
    
    def _identify_target_type(self, target: str) -> str:
        """Identify type of target (IP, domain, URL, etc.)"""
        if not target:
            return 'unknown'
        
        try:
            ipaddress.ip_address(target)
            return 'ip_address'
        except:
            pass
        
        if target.startswith(('http://', 'https://')):
            return 'url'
        elif '.' in target and not target.startswith(('/', '\\')):
            return 'domain'
        elif ':' in target:
            return 'host_port'
        else:
            return 'other'

