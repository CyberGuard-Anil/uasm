"""
API Security Scanner Module for UASM
Handles API endpoint discovery and security testing
"""

import requests
import json
import time
import threading
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from uasm.core.logger import create_module_logger, log_vulnerability_found, log_finding
from uasm.utils.helpers import generate_user_agent
from uasm.utils.parsers import parse_openapi_spec, parse_swagger_spec


class APISecurityScanner:
    """API security scanner for REST and GraphQL endpoints"""
    
    def __init__(self, config, target: str, database=None):
        """Initialize API security scanner"""
        self.config = config
        self.target = target
        self.db = database
        self.logger = create_module_logger('APISecurityScanner')
        
        # API security configuration
        self.api_config = self.config.get_section('api_security')
        self.threads = self.api_config.get('threads', 10)
        self.timeout = self.api_config.get('timeout', 30)
        
        # Common API endpoints to check
        self.swagger_endpoints = self.api_config.get('swagger_endpoints', [
            '/swagger.json', '/api/swagger.json', '/v1/swagger.json',
            '/swagger/v1/swagger.json', '/api-docs', '/docs'
        ])
        
        self.openapi_endpoints = self.api_config.get('openapi_endpoints', [
            '/openapi.json', '/api/openapi.json', '/openapi/openapi.json'
        ])
        
        self.common_api_paths = self.api_config.get('common_paths', [
            '/api', '/v1', '/v2', '/v3', '/rest', '/graphql'
        ])
        
        # HTTP session
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': generate_user_agent()})
        
        # Scan results
        self.results = {
            'api_endpoints': [],
            'vulnerabilities': [],
            'findings': [],
            'specifications': [],
            'statistics': {}
        }
        
        # Control flags
        self.running = False
        self._stop_event = threading.Event()
        
        # Discovered APIs
        self.discovered_apis: Set[str] = set()
        
        self.logger.info(f"API security scanner initialized for target: {target}")
    
    def run(self) -> Dict[str, Any]:
        """Run API security assessment"""
        self.running = True
        self._stop_event.clear()
        
        try:
            self.logger.info("🔍 Starting API security assessment...")
            
            start_time = time.time()
            
            # API discovery
            self._discover_api_endpoints()
            
            if self.results['api_endpoints']:
                # API specification analysis
                self._analyze_api_specifications()
                
                # API security testing
                self._test_api_security()
                
                # GraphQL specific testing
                self._test_graphql_endpoints()
            
            # Calculate statistics
            self._calculate_statistics()
            
            duration = time.time() - start_time
            self.logger.info(f"✅ API security assessment completed in {duration:.2f} seconds")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ API security assessment failed: {str(e)}")
            raise
        finally:
            self.running = False
    
    def _discover_api_endpoints(self):
        """Discover API endpoints"""
        self.logger.info("🔍 Discovering API endpoints...")
        
        # Prepare base URLs to test
        base_urls = self._prepare_base_urls()
        
        for base_url in base_urls:
            if self._stop_event.is_set():
                break
                
            # Check for API documentation endpoints
            self._check_documentation_endpoints(base_url)
            
            # Check common API paths
            self._check_common_api_paths(base_url)
            
            # Check for GraphQL endpoints
            self._check_graphql_endpoints(base_url)
    
    def _prepare_base_urls(self) -> List[str]:
        """Prepare base URLs for API testing"""
        base_urls = []
        
        # If target is a domain, try common protocols
        if not self.target.startswith(('http://', 'https://')):
            base_urls = [
                f'https://{self.target}',
                f'http://{self.target}',
                f'https://api.{self.target}',
                f'http://api.{self.target}'
            ]
        else:
            base_urls = [self.target]
        
        return base_urls
    
    def _check_documentation_endpoints(self, base_url: str):
        """Check for API documentation endpoints"""
        all_endpoints = self.swagger_endpoints + self.openapi_endpoints
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_endpoint = {
                executor.submit(self._test_documentation_endpoint, base_url, endpoint): endpoint
                for endpoint in all_endpoints
            }
            
            for future in as_completed(future_to_endpoint):
                if self._stop_event.is_set():
                    break
                
                endpoint = future_to_endpoint[future]
                try:
                    result = future.result()
                    if result:
                        self.results['specifications'].append(result)
                        
                        self._add_finding(
                            category='api',
                            subcategory='documentation_discovery',
                            title=f'API Documentation Found: {result["type"]}',
                            description=f'API documentation endpoint discovered at {result["url"]}',
                            severity='info',
                            target=result['url']
                        )
                        
                        # Check if documentation is publicly accessible
                        if result.get('public_access', False):
                            self._add_vulnerability(
                                title='Publicly Accessible API Documentation',
                                description=f'API documentation at {result["url"]} is publicly accessible',
                                severity='low',
                                cvss_score=2.0,
                                target_url=result['url'],
                                remediation='Restrict access to API documentation or ensure it doesn\'t contain sensitive information'
                            )
                            
                except Exception as e:
                    self.logger.debug(f"Error testing endpoint {endpoint}: {str(e)}")
    
    def _test_documentation_endpoint(self, base_url: str, endpoint: str) -> Optional[Dict[str, Any]]:
        """Test a single documentation endpoint"""
        url = urljoin(base_url, endpoint)
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                
                if 'application/json' in content_type:
                    try:
                        spec_data = response.json()
                        spec_type = self._identify_spec_type(spec_data, endpoint)
                        
                        return {
                            'url': url,
                            'type': spec_type,
                            'data': spec_data,
                            'public_access': True,
                            'endpoints_count': self._count_endpoints_in_spec(spec_data),
                            'authentication_required': self._check_auth_in_spec(spec_data)
                        }
                    except json.JSONDecodeError:
                        pass
                
                elif 'text/html' in content_type and any(keyword in response.text.lower() 
                                                        for keyword in ['swagger', 'api', 'openapi']):
                    return {
                        'url': url,
                        'type': 'swagger-ui',
                        'public_access': True,
                        'html_content': True
                    }
        
        except Exception:
            pass
        
        return None
    
    def _identify_spec_type(self, spec_data: Dict, endpoint: str) -> str:
        """Identify API specification type"""
        if 'swagger' in spec_data:
            return 'swagger'
        elif 'openapi' in spec_data:
            return 'openapi'
        elif 'swagger' in endpoint.lower():
            return 'swagger'
        elif 'openapi' in endpoint.lower():
            return 'openapi'
        else:
            return 'unknown'
    
    def _count_endpoints_in_spec(self, spec_data: Dict) -> int:
        """Count endpoints in API specification"""
        paths = spec_data.get('paths', {})
        total_endpoints = 0
        
        for path, methods in paths.items():
            if isinstance(methods, dict):
                # Count HTTP methods for this path
                http_methods = [m for m in methods.keys() if m.lower() in 
                              ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']]
                total_endpoints += len(http_methods)
        
        return total_endpoints
    
    def _check_auth_in_spec(self, spec_data: Dict) -> bool:
        """Check if authentication is defined in spec"""
        # Check for security definitions
        if 'securityDefinitions' in spec_data or 'security' in spec_data:
            return True
        
        if 'components' in spec_data and 'securitySchemes' in spec_data['components']:
            return True
        
        return False
    
    def _check_common_api_paths(self, base_url: str):
        """Check common API paths"""
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {
                executor.submit(self._test_api_path, base_url, path): path
                for path in self.common_api_paths
            }
            
            for future in as_completed(future_to_path):
                if self._stop_event.is_set():
                    break
                
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        self.results['api_endpoints'].append(result)
                        self.discovered_apis.add(result['url'])
                        
                        self._add_finding(
                            category='api',
                            subcategory='endpoint_discovery',
                            title=f'API Endpoint Found: {result["path"]}',
                            description=f'API endpoint discovered at {result["url"]}',
                            severity='info',
                            target=result['url']
                        )
                        
                except Exception as e:
                    self.logger.debug(f"Error testing path {path}: {str(e)}")
    
    def _test_api_path(self, base_url: str, path: str) -> Optional[Dict[str, Any]]:
        """Test a single API path"""
        url = urljoin(base_url, path)
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Consider it an API endpoint if we get certain responses
            if response.status_code in [200, 401, 403, 404, 405]:
                content_type = response.headers.get('Content-Type', '').lower()
                
                # Check for API-like responses
                if (response.status_code == 401 or 
                    'application/json' in content_type or
                    'api' in response.text.lower()[:200]):
                    
                    return {
                        'url': url,
                        'path': path,
                        'status_code': response.status_code,
                        'content_type': content_type,
                        'authentication_required': response.status_code == 401,
                        'methods_allowed': self._check_allowed_methods(url),
                        'response_size': len(response.content)
                    }
        
        except Exception:
            pass
        
        return None
    
    def _check_allowed_methods(self, url: str) -> List[str]:
        """Check allowed HTTP methods for an endpoint"""
        try:
            response = self.session.options(url, timeout=self.timeout)
            allow_header = response.headers.get('Allow', '')
            
            if allow_header:
                return [method.strip() for method in allow_header.split(',')]
            
            # If OPTIONS doesn't work, try common methods
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
            allowed_methods = []
            
            for method in methods:
                try:
                    test_response = self.session.request(method, url, timeout=5)
                    if test_response.status_code != 405:  # Method not allowed
                        allowed_methods.append(method)
                except:
                    continue
            
            return allowed_methods
            
        except Exception:
            return []
    
    def _check_graphql_endpoints(self, base_url: str):
        """Check for GraphQL endpoints"""
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/query']
        
        for path in graphql_paths:
            if self._stop_event.is_set():
                break
                
            url = urljoin(base_url, path)
            
            # Test GraphQL introspection
            if self._test_graphql_introspection(url):
                self.results['api_endpoints'].append({
                    'url': url,
                    'path': path,
                    'type': 'graphql',
                    'introspection_enabled': True
                })
                
                self._add_vulnerability(
                    title='GraphQL Introspection Enabled',
                    description=f'GraphQL introspection is enabled at {url}',
                    severity='medium',
                    cvss_score=4.0,
                    target_url=url,
                    remediation='Disable GraphQL introspection in production'
                )
    
    def _test_graphql_introspection(self, url: str) -> bool:
        """Test if GraphQL introspection is enabled"""
        introspection_query = {
            "query": "{ __schema { types { name } } }"
        }
        
        try:
            response = self.session.post(
                url, 
                json=introspection_query, 
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    return '__schema' in str(data)
                except:
                    pass
        
        except Exception:
            pass
        
        return False
    
    def _analyze_api_specifications(self):
        """Analyze discovered API specifications"""
        self.logger.info("🔍 Analyzing API specifications...")
        
        for spec in self.results['specifications']:
            if 'data' in spec:
                spec_data = spec['data']
                spec_type = spec['type']
                
                if spec_type in ['swagger', 'openapi']:
                    parsed_spec = parse_openapi_spec(spec_data)
                    
                    # Extract endpoints from specification
                    endpoints = self._extract_endpoints_from_spec(parsed_spec, spec['url'])
                    self.results['api_endpoints'].extend(endpoints)
                    
                    # Check for security issues in specification
                    self._analyze_spec_security(parsed_spec, spec['url'])
    
    def _extract_endpoints_from_spec(self, parsed_spec: Dict, base_url: str) -> List[Dict]:
        """Extract endpoints from parsed API specification"""
        endpoints = []
        paths = parsed_spec.get('paths', {})
        
        for path, methods in paths.items():
            if isinstance(methods, dict):
                for method, details in methods.items():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                        endpoint_url = urljoin(base_url.replace('/swagger.json', '').replace('/openapi.json', ''), path)
                        
                        endpoints.append({
                            'url': endpoint_url,
                            'path': path,
                            'method': method.upper(),
                            'summary': details.get('summary', ''),
                            'parameters': details.get('parameters', []),
                            'security': details.get('security', []),
                            'from_specification': True
                        })
        
        return endpoints
    
    def _analyze_spec_security(self, parsed_spec: Dict, spec_url: str):
        """Analyze security aspects of API specification"""
        
        # Check if security is defined globally
        if not parsed_spec.get('security'):
            self._add_vulnerability(
                title='No Global Security Defined in API Spec',
                description='API specification does not define global security requirements',
                severity='medium',
                cvss_score=5.0,
                target_url=spec_url,
                remediation='Define global security requirements in API specification'
            )
        
        # Check for endpoints without security
        paths = parsed_spec.get('paths', {})
        unsecured_endpoints = []
        
        for path, methods in paths.items():
            if isinstance(methods, dict):
                for method, details in methods.items():
                    if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                        if not details.get('security') and not parsed_spec.get('security'):
                            unsecured_endpoints.append(f"{method.upper()} {path}")
        
        if unsecured_endpoints:
            self._add_vulnerability(
                title='Unsecured API Endpoints',
                description=f'Found {len(unsecured_endpoints)} endpoints without security requirements',
                severity='medium',
                cvss_score=5.0,
                target_url=spec_url,
                remediation='Add security requirements to all API endpoints'
            )
    
    def _test_api_security(self):
        """Test API security"""
        self.logger.info("🔍 Testing API security...")
        
        for endpoint in self.results['api_endpoints']:
            if self._stop_event.is_set():
                break
                
            url = endpoint['url']
            
            # Test authentication bypass
            self._test_authentication_bypass(endpoint)
            
            # Test for CORS misconfigurations
            self._test_cors_configuration(url)
            
            # Test for injection vulnerabilities
            self._test_injection_vulnerabilities(endpoint)
            
            # Test rate limiting
            self._test_rate_limiting(url)
    
    def _test_authentication_bypass(self, endpoint: Dict):
        """Test for authentication bypass"""
        url = endpoint['url']
        
        # Test with different headers
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'}
        ]
        
        for headers in bypass_headers:
            try:
                response = self.session.get(url, headers=headers, timeout=self.timeout)
                
                if response.status_code == 200 and endpoint.get('authentication_required'):
                    self._add_vulnerability(
                        title='Authentication Bypass via Headers',
                        description=f'Authentication bypass possible using {list(headers.keys())[0]} header',
                        severity='high',
                        cvss_score=7.5,
                        target_url=url,
                        remediation='Properly validate authentication regardless of forwarded headers'
                    )
                    break
                    
            except Exception:
                continue
    
    def _test_cors_configuration(self, url: str):
        """Test CORS configuration"""
        try:
            # Test CORS with malicious origin
            headers = {'Origin': 'https://evil.com'}
            response = self.session.options(url, headers=headers, timeout=self.timeout)
            
            access_control_origin = response.headers.get('Access-Control-Allow-Origin')
            
            if access_control_origin == '*':
                self._add_vulnerability(
                    title='Overly Permissive CORS Policy',
                    description='API allows requests from any origin (*)',
                    severity='medium',
                    cvss_score=5.0,
                    target_url=url,
                    remediation='Restrict CORS to specific trusted origins'
                )
            
            elif access_control_origin == 'https://evil.com':
                self._add_vulnerability(
                    title='CORS Origin Reflection',
                    description='API reflects arbitrary origins in Access-Control-Allow-Origin',
                    severity='high',
                    cvss_score=6.5,
                    target_url=url,
                    remediation='Validate and whitelist allowed origins'
                )
                
        except Exception:
            pass
    
    def _test_injection_vulnerabilities(self, endpoint: Dict):
        """Test for injection vulnerabilities"""
        url = endpoint['url']
        method = endpoint.get('method', 'GET')
        
        # SQL injection payloads
        sql_payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users; --"]
        
        # NoSQL injection payloads  
        nosql_payloads = ['{"$ne": null}', '{"$gt": ""}']
        
        # Test different injection points
        for payload in sql_payloads[:2]:  # Limit testing
            if self._stop_event.is_set():
                break
                
            try:
                if method == 'GET':
                    test_url = f"{url}?id={payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    response = self.session.post(url, json={'id': payload}, timeout=self.timeout)
                
                # Check for SQL error messages
                error_patterns = ['sql', 'mysql', 'postgresql', 'oracle', 'sqlite', 'syntax error']
                response_text = response.text.lower()
                
                if any(pattern in response_text for pattern in error_patterns):
                    self._add_vulnerability(
                        title='Potential SQL Injection',
                        description=f'SQL error messages detected when testing injection payloads',
                        severity='high',
                        cvss_score=8.0,
                        target_url=url,
                        remediation='Use parameterized queries and input validation'
                    )
                    break
                    
            except Exception:
                continue
    
    def _test_rate_limiting(self, url: str):
        """Test rate limiting"""
        try:
            # Send multiple rapid requests
            responses = []
            for _ in range(10):
                response = self.session.get(url, timeout=5)
                responses.append(response.status_code)
                time.sleep(0.1)
            
            # Check if any requests were rate limited
            rate_limited = any(status in [429, 503] for status in responses)
            
            if not rate_limited and all(status == 200 for status in responses):
                self._add_vulnerability(
                    title='No Rate Limiting Detected',
                    description='API endpoint does not implement rate limiting',
                    severity='medium',
                    cvss_score=4.0,
                    target_url=url,
                    remediation='Implement rate limiting to prevent abuse'
                )
                
        except Exception:
            pass
    
    def _test_graphql_endpoints(self):
        """Test GraphQL specific vulnerabilities"""
        graphql_endpoints = [ep for ep in self.results['api_endpoints'] if ep.get('type') == 'graphql']
        
        for endpoint in graphql_endpoints:
            if self._stop_event.is_set():
                break
                
            self._test_graphql_depth_limiting(endpoint['url'])
            self._test_graphql_query_complexity(endpoint['url'])
    
    def _test_graphql_depth_limiting(self, url: str):
        """Test GraphQL depth limiting"""
        # Deep nested query
        deep_query = {
            "query": "{ user { posts { comments { author { posts { comments { author { name } } } } } } } }"
        }
        
        try:
            response = self.session.post(url, json=deep_query, timeout=self.timeout)
            
            if response.status_code == 200:
                self._add_vulnerability(
                    title='GraphQL Depth Limiting Not Implemented',
                    description='GraphQL endpoint allows deeply nested queries',
                    severity='medium',
                    cvss_score=4.0,
                    target_url=url,
                    remediation='Implement query depth limiting'
                )
                
        except Exception:
            pass
    
    def _test_graphql_query_complexity(self, url: str):
        """Test GraphQL query complexity limiting"""
        # Complex query with multiple fields
        complex_query = {
            "query": "{ users { id name email posts { id title content comments { id content } } } }"
        }
        
        try:
            response = self.session.post(url, json=complex_query, timeout=self.timeout)
            
            if response.status_code == 200:
                self._add_finding(
                    category='api',
                    subcategory='graphql_security',
                    title='GraphQL Complex Query Executed',
                    description='GraphQL endpoint executed complex query without restrictions',
                    severity='info',
                    target=url
                )
                
        except Exception:
            pass
    
    def _calculate_statistics(self):
        """Calculate API security statistics"""
        self.results['statistics'] = {
            'total_api_endpoints': len(self.results['api_endpoints']),
            'total_specifications': len(self.results['specifications']),
            'graphql_endpoints': len([ep for ep in self.results['api_endpoints'] if ep.get('type') == 'graphql']),
            'rest_endpoints': len([ep for ep in self.results['api_endpoints'] if ep.get('type') != 'graphql']),
            'authenticated_endpoints': len([ep for ep in self.results['api_endpoints'] if ep.get('authentication_required')]),
            'vulnerabilities_found': len(self.results['vulnerabilities']),
            'findings_count': len(self.results['findings'])
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
            'module': 'api',
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
            'module': 'api',
            'discovered_at': time.time()
        }
        
        self.results['findings'].append(finding)
        log_finding(self.logger, category, title, target)
    
    def stop(self):
        """Stop the API security scan"""
        self.logger.info("🛑 Stopping API security scan...")
        self._stop_event.set()
        self.running = False

