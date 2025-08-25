"""
Cloud Reconnaissance Module for UASM
Handles cloud asset discovery across AWS, GCP, and Azure
"""

import requests
import threading
import time
from typing import Dict, List, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from uasm.core.logger import create_module_logger, log_vulnerability_found, log_finding
from uasm.utils.helpers import generate_user_agent, clean_domain


class CloudRecon:
    """Cloud reconnaissance scanner for AWS, GCP, and Azure assets"""
    
    def __init__(self, config, target: str, database=None):
        """Initialize cloud reconnaissance scanner"""
        self.config = config
        self.target = clean_domain(target)
        self.db = database
        self.logger = create_module_logger('CloudRecon')
        
        # Cloud recon configuration
        self.cloud_config = self.config.get_section('cloud_recon')
        self.threads = self.cloud_config.get('threads', 10)
        self.timeout = self.cloud_config.get('timeout', 30)
        
        # Cloud platform configurations
        self.aws_config = self.cloud_config.get('aws', {})
        self.gcp_config = self.cloud_config.get('gcp', {})
        self.azure_config = self.cloud_config.get('azure', {})
        
        # HTTP session
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': generate_user_agent()})
        
        # Scan results
        self.results = {
            'cloud_assets': [],
            'vulnerabilities': [],
            'findings': [],
            'statistics': {}
        }
        
        # Control flags
        self.running = False
        self._stop_event = threading.Event()
        
        # Discovered cloud assets
        self.discovered_assets: Set[str] = set()
        
        self.logger.info(f"Cloud reconnaissance initialized for target: {target}")
    
    def run(self) -> Dict[str, Any]:
        """Run cloud asset reconnaissance"""
        self.running = True
        self._stop_event.clear()
        
        try:
            self.logger.info("🔍 Starting cloud asset reconnaissance...")
            
            start_time = time.time()
            
            # AWS reconnaissance
            self._scan_aws_assets()
            
            # Google Cloud reconnaissance
            self._scan_gcp_assets()
            
            # Azure reconnaissance  
            self._scan_azure_assets()
            
            # Calculate statistics
            self._calculate_statistics()
            
            duration = time.time() - start_time
            self.logger.info(f"✅ Cloud reconnaissance completed in {duration:.2f} seconds")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Cloud reconnaissance failed: {str(e)}")
            raise
        finally:
            self.running = False
    
    def _scan_aws_assets(self):
        """Scan for AWS assets"""
        self.logger.info("🔍 Scanning AWS assets...")
        
        # S3 bucket enumeration
        self._enumerate_s3_buckets()
        
        # CloudFront distributions
        self._check_cloudfront_distributions()
        
        # ElasticBeanstalk applications
        self._check_elasticbeanstalk_apps()
    
    def _enumerate_s3_buckets(self):
        """Enumerate S3 buckets"""
        bucket_patterns = self.aws_config.get('s3_bucket_patterns', [
            '{target}', '{target}-dev', '{target}-prod', '{target}-backup',
            '{target}-assets', '{target}-static', '{target}-uploads',
            '{target}-logs', '{target}-data', '{target}-staging'
        ])
        
        # Generate bucket names
        bucket_names = []
        target_clean = self.target.replace('.', '-').replace('_', '-')
        
        for pattern in bucket_patterns:
            bucket_name = pattern.format(target=target_clean)
            bucket_names.append(bucket_name)
            
            # Also try with different formats
            bucket_names.append(bucket_name.replace('-', ''))
            bucket_names.append(bucket_name.replace('-', '.'))
        
        # Remove duplicates
        bucket_names = list(set(bucket_names))
        
        # Test bucket names
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_bucket = {
                executor.submit(self._test_s3_bucket, bucket_name): bucket_name
                for bucket_name in bucket_names
            }
            
            for future in as_completed(future_to_bucket):
                if self._stop_event.is_set():
                    break
                
                bucket_name = future_to_bucket[future]
                try:
                    result = future.result()
                    if result:
                        self.results['cloud_assets'].append(result)
                        self.discovered_assets.add(result['url'])
                        
                        self._add_finding(
                            category='cloud',
                            subcategory='s3_discovery',
                            title=f'S3 Bucket Found: {bucket_name}',
                            description=f'AWS S3 bucket discovered: {result["url"]}',
                            severity='info',
                            target=result['url']
                        )
                        
                        # Check for public access
                        if result.get('public_access'):
                            self._add_vulnerability(
                                title='Publicly Accessible S3 Bucket',
                                description=f'S3 bucket {bucket_name} is publicly accessible',
                                severity='high',
                                cvss_score=7.5,
                                target_url=result['url'],
                                remediation='Review and restrict S3 bucket permissions'
                            )
                            
                except Exception as e:
                    self.logger.debug(f"Error testing S3 bucket {bucket_name}: {str(e)}")
    
    def _test_s3_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Test if an S3 bucket exists and is accessible"""
        # Try different S3 URL formats
        s3_urls = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://s3.amazonaws.com/{bucket_name}/",
            f"http://{bucket_name}.s3.amazonaws.com/",
            f"http://s3.amazonaws.com/{bucket_name}/"
        ]
        
        for url in s3_urls:
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                # Bucket exists if we get 200, 403, or specific 404 with S3 error
                if response.status_code == 200:
                    return {
                        'type': 's3_bucket',
                        'provider': 'aws',
                        'name': bucket_name,
                        'url': url,
                        'public_access': True,
                        'status_code': response.status_code,
                        'listable': 'ListBucketResult' in response.text,
                        'size': len(response.content)
                    }
                
                elif response.status_code == 403:
                    # Bucket exists but access denied
                    return {
                        'type': 's3_bucket',
                        'provider': 'aws',
                        'name': bucket_name,
                        'url': url,
                        'public_access': False,
                        'status_code': response.status_code,
                        'access_denied': True
                    }
                
                elif (response.status_code == 404 and 
                      'NoSuchBucket' not in response.text and 
                      's3' in response.text.lower()):
                    # Bucket exists but different error
                    return {
                        'type': 's3_bucket',
                        'provider': 'aws',
                        'name': bucket_name,
                        'url': url,
                        'public_access': False,
                        'status_code': response.status_code
                    }
                    
            except Exception:
                continue
        
        return None
    
    def _check_cloudfront_distributions(self):
        """Check for CloudFront distributions"""
        # Common CloudFront patterns
        cf_patterns = [
            f"{self.target.replace('.', '')}.cloudfront.net",
            f"{self.target.replace('.', '-')}.cloudfront.net",
            f"cdn.{self.target}",
            f"assets.{self.target}",
            f"static.{self.target}"
        ]
        
        for pattern in cf_patterns:
            if self._stop_event.is_set():
                break
                
            try:
                url = f"https://{pattern}"
                response = self.session.get(url, timeout=self.timeout)
                
                # Check CloudFront headers
                if ('cloudfront' in response.headers.get('Server', '').lower() or 
                    'x-amz-cf-id' in response.headers or
                    'x-cache' in response.headers):
                    
                    self.results['cloud_assets'].append({
                        'type': 'cloudfront',
                        'provider': 'aws',
                        'url': url,
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    })
                    
                    self._add_finding(
                        category='cloud',
                        subcategory='cloudfront_discovery',
                        title=f'CloudFront Distribution Found: {pattern}',
                        description=f'AWS CloudFront distribution discovered',
                        severity='info',
                        target=url
                    )
                    
            except Exception as e:
                self.logger.debug(f"Error checking CloudFront {pattern}: {str(e)}")
    
    def _check_elasticbeanstalk_apps(self):
        """Check for Elastic Beanstalk applications"""
        # Common EB patterns
        eb_patterns = [
            f"{self.target.replace('.', '-')}.elasticbeanstalk.com",
            f"{self.target.replace('.', '')}.elasticbeanstalk.com"
        ]
        
        aws_regions = self.aws_config.get('regions', ['us-east-1', 'us-west-2'])
        
        for region in aws_regions:
            for pattern in eb_patterns:
                if self._stop_event.is_set():
                    break
                    
                try:
                    # EB URL format: app-name.region.elasticbeanstalk.com
                    url = f"https://{pattern.replace('elasticbeanstalk.com', f'{region}.elasticbeanstalk.com')}"
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if response.status_code in [200, 403, 404]:
                        # Check if it's actually an EB app
                        if ('elasticbeanstalk' in response.text.lower() or 
                            response.status_code == 200):
                            
                            self.results['cloud_assets'].append({
                                'type': 'elastic_beanstalk',
                                'provider': 'aws',
                                'url': url,
                                'region': region,
                                'status_code': response.status_code
                            })
                            
                            self._add_finding(
                                category='cloud',
                                subcategory='elasticbeanstalk_discovery',
                                title=f'Elastic Beanstalk App Found',
                                description=f'AWS Elastic Beanstalk application discovered in {region}',
                                severity='info',
                                target=url
                            )
                            
                except Exception as e:
                    self.logger.debug(f"Error checking Elastic Beanstalk {pattern} in {region}: {str(e)}")
    
    def _scan_gcp_assets(self):
        """Scan for Google Cloud Platform assets"""
        self.logger.info("🔍 Scanning GCP assets...")
        
        # Google Cloud Storage buckets
        self._enumerate_gcs_buckets()
        
        # App Engine applications
        self._check_appengine_apps()
        
        # Cloud Functions
        self._check_cloud_functions()
    
    def _enumerate_gcs_buckets(self):
        """Enumerate Google Cloud Storage buckets"""
        bucket_patterns = self.gcp_config.get('bucket_patterns', [
            '{target}', '{target}-storage', '{target}-backup'
        ])
        
        bucket_names = []
        target_clean = self.target.replace('.', '-').replace('_', '-')
        
        for pattern in bucket_patterns:
            bucket_name = pattern.format(target=target_clean)
            bucket_names.append(bucket_name)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_bucket = {
                executor.submit(self._test_gcs_bucket, bucket_name): bucket_name
                for bucket_name in bucket_names
            }
            
            for future in as_completed(future_to_bucket):
                if self._stop_event.is_set():
                    break
                
                bucket_name = future_to_bucket[future]
                try:
                    result = future.result()
                    if result:
                        self.results['cloud_assets'].append(result)
                        
                        self._add_finding(
                            category='cloud',
                            subcategory='gcs_discovery',
                            title=f'GCS Bucket Found: {bucket_name}',
                            description=f'Google Cloud Storage bucket discovered',
                            severity='info',
                            target=result['url']
                        )
                        
                        if result.get('public_access'):
                            self._add_vulnerability(
                                title='Publicly Accessible GCS Bucket',
                                description=f'GCS bucket {bucket_name} is publicly accessible',
                                severity='high',
                                cvss_score=7.5,
                                target_url=result['url'],
                                remediation='Review and restrict GCS bucket permissions'
                            )
                            
                except Exception as e:
                    self.logger.debug(f"Error testing GCS bucket {bucket_name}: {str(e)}")
    
    def _test_gcs_bucket(self, bucket_name: str) -> Optional[Dict[str, Any]]:
        """Test if a GCS bucket exists"""
        url = f"https://storage.googleapis.com/{bucket_name}/"
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                return {
                    'type': 'gcs_bucket',
                    'provider': 'gcp',
                    'name': bucket_name,
                    'url': url,
                    'public_access': True,
                    'status_code': response.status_code
                }
            elif response.status_code == 403:
                return {
                    'type': 'gcs_bucket',
                    'provider': 'gcp',
                    'name': bucket_name,
                    'url': url,
                    'public_access': False,
                    'status_code': response.status_code,
                    'access_denied': True
                }
                
        except Exception:
            pass
        
        return None
    
    def _check_appengine_apps(self):
        """Check for App Engine applications"""
        app_patterns = [
            f"{self.target.replace('.', '-')}.appspot.com",
            f"{self.target.replace('.', '')}.appspot.com"
        ]
        
        for pattern in app_patterns:
            if self._stop_event.is_set():
                break
                
            try:
                url = f"https://{pattern}"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code in [200, 403, 404]:
                    self.results['cloud_assets'].append({
                        'type': 'app_engine',
                        'provider': 'gcp',
                        'url': url,
                        'status_code': response.status_code
                    })
                    
                    self._add_finding(
                        category='cloud',
                        subcategory='appengine_discovery',
                        title=f'App Engine App Found: {pattern}',
                        description=f'Google App Engine application discovered',
                        severity='info',
                        target=url
                    )
                    
            except Exception as e:
                self.logger.debug(f"Error checking App Engine {pattern}: {str(e)}")
    
    def _check_cloud_functions(self):
        """Check for Google Cloud Functions"""
        # Cloud Functions URL patterns
        cf_patterns = [
            f"{self.target.replace('.', '-')}-function",
            f"{self.target.replace('.', '')}-api"
        ]
        
        gcp_regions = ['us-central1', 'us-east1', 'europe-west1']
        
        for region in gcp_regions:
            for pattern in cf_patterns:
                if self._stop_event.is_set():
                    break
                    
                try:
                    # Cloud Functions URL format
                    url = f"https://{region}-PROJECT_ID.cloudfunctions.net/{pattern}"
                    # This is a simplified check - real implementation would need project IDs
                    
                    self.logger.debug(f"Cloud Functions check would test: {url}")
                    
                except Exception as e:
                    self.logger.debug(f"Error checking Cloud Function {pattern}: {str(e)}")
    
    def _scan_azure_assets(self):
        """Scan for Microsoft Azure assets"""
        self.logger.info("🔍 Scanning Azure assets...")
        
        # Azure Blob Storage containers
        self._enumerate_azure_blobs()
        
        # Azure App Service
        self._check_azure_app_services()
        
        # Azure Functions
        self._check_azure_functions()
    
    def _enumerate_azure_blobs(self):
        """Enumerate Azure Blob Storage containers"""
        container_patterns = self.azure_config.get('container_patterns', [
            '{target}', '{target}-storage'
        ])
        
        # Common Azure storage account patterns
        storage_account_patterns = [
            self.target.replace('.', '').replace('-', ''),
            f"{self.target.replace('.', '').replace('-', '')}storage",
            f"{self.target.replace('.', '').replace('-', '')}data"
        ]
        
        for storage_account in storage_account_patterns:
            for container_pattern in container_patterns:
                if self._stop_event.is_set():
                    break
                    
                container_name = container_pattern.format(target=self.target.replace('.', '-'))
                
                # Azure Blob URL format
                url = f"https://{storage_account}.blob.core.windows.net/{container_name}/"
                
                try:
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if response.status_code in [200, 403]:
                        self.results['cloud_assets'].append({
                            'type': 'azure_blob',
                            'provider': 'azure',
                            'storage_account': storage_account,
                            'container': container_name,
                            'url': url,
                            'public_access': response.status_code == 200,
                            'status_code': response.status_code
                        })
                        
                        self._add_finding(
                            category='cloud',
                            subcategory='azure_blob_discovery',
                            title=f'Azure Blob Container Found: {container_name}',
                            description=f'Azure Blob Storage container discovered',
                            severity='info',
                            target=url
                        )
                        
                        if response.status_code == 200:
                            self._add_vulnerability(
                                title='Publicly Accessible Azure Blob Container',
                                description=f'Azure Blob container {container_name} is publicly accessible',
                                severity='high',
                                cvss_score=7.5,
                                target_url=url,
                                remediation='Review and restrict Azure Blob container permissions'
                            )
                            
                except Exception as e:
                    self.logger.debug(f"Error checking Azure Blob {url}: {str(e)}")
    
    def _check_azure_app_services(self):
        """Check for Azure App Service applications"""
        app_patterns = [
            f"{self.target.replace('.', '-')}.azurewebsites.net",
            f"{self.target.replace('.', '')}.azurewebsites.net"
        ]
        
        for pattern in app_patterns:
            if self._stop_event.is_set():
                break
                
            try:
                url = f"https://{pattern}"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code in [200, 403, 404]:
                    # Check for Azure-specific headers or content
                    if ('azure' in response.headers.get('Server', '').lower() or
                        'azurewebsites' in response.text.lower()):
                        
                        self.results['cloud_assets'].append({
                            'type': 'azure_app_service',
                            'provider': 'azure',
                            'url': url,
                            'status_code': response.status_code,
                            'server': response.headers.get('Server', '')
                        })
                        
                        self._add_finding(
                            category='cloud',
                            subcategory='azure_app_service_discovery',
                            title=f'Azure App Service Found: {pattern}',
                            description=f'Azure App Service application discovered',
                            severity='info',
                            target=url
                        )
                        
            except Exception as e:
                self.logger.debug(f"Error checking Azure App Service {pattern}: {str(e)}")
    
    def _check_azure_functions(self):
        """Check for Azure Functions"""
        function_patterns = [
            f"{self.target.replace('.', '-')}.azurewebsites.net/api",
            f"{self.target.replace('.', '')}-func.azurewebsites.net"
        ]
        
        for pattern in function_patterns:
            if self._stop_event.is_set():
                break
                
            try:
                url = f"https://{pattern}"
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code in [200, 401, 403, 404]:
                    # Azure Functions typically return 401 without proper auth
                    if (response.status_code == 401 or 
                        'azure' in response.headers.get('Server', '').lower()):
                        
                        self.results['cloud_assets'].append({
                            'type': 'azure_function',
                            'provider': 'azure',
                            'url': url,
                            'status_code': response.status_code
                        })
                        
                        self._add_finding(
                            category='cloud',
                            subcategory='azure_function_discovery',
                            title=f'Azure Function Found: {pattern}',
                            description=f'Azure Function application discovered',
                            severity='info',
                            target=url
                        )
                        
            except Exception as e:
                self.logger.debug(f"Error checking Azure Function {pattern}: {str(e)}")
    
    def _calculate_statistics(self):
        """Calculate cloud reconnaissance statistics"""
        cloud_assets = self.results['cloud_assets']
        
        # Group by provider
        provider_stats = {}
        type_stats = {}
        
        for asset in cloud_assets:
            provider = asset.get('provider', 'unknown')
            asset_type = asset.get('type', 'unknown')
            
            provider_stats[provider] = provider_stats.get(provider, 0) + 1
            type_stats[asset_type] = type_stats.get(asset_type, 0) + 1
        
        # Public vs private assets
        public_assets = len([a for a in cloud_assets if a.get('public_access', False)])
        private_assets = len(cloud_assets) - public_assets
        
        self.results['statistics'] = {
            'total_cloud_assets': len(cloud_assets),
            'provider_distribution': provider_stats,
            'asset_type_distribution': type_stats,
            'public_assets': public_assets,
            'private_assets': private_assets,
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
            'module': 'cloud',
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
            'module': 'cloud',
            'discovered_at': time.time()
        }
        
        self.results['findings'].append(finding)
        log_finding(self.logger, category, title, target)
    
    def stop(self):
        """Stop the cloud reconnaissance scan"""
        self.logger.info("🛑 Stopping cloud reconnaissance...")
        self._stop_event.set()
        self.running = False

