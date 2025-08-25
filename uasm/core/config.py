"""
Configuration Manager for UASM
Handles loading and managing configuration settings
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List, Union


class Config:
    """Configuration manager for UASM"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration"""
        self.config_data = {}
        self._load_default_config()
        
        if config_path and Path(config_path).exists():
            self._load_config_file(config_path)
        elif Path("config.yaml").exists():
            self._load_config_file("config.yaml")
        
        # Override with environment variables
        self._load_env_overrides()
    
    def _load_default_config(self):
        """Load default configuration"""
        self.config_data = {
            'general': {
                'max_threads': 50,
                'scan_timeout': 3600,
                'user_agent': 'UASM/1.0 Security Scanner',
                'rate_limit': 10
            },
            'database': {
                'type': 'sqlite',
                'name': 'uasm_results.db',
                'host': 'localhost',
                'port': 5432,
                'username': '',
                'password': ''
            },
            'output': {
                'base_dir': 'scans',
                'save_raw_data': True,
                'compress_results': False
            },
            'logging': {
                'level': 'INFO',
                'file': 'uasm.log',
                'max_file_size': '10MB',
                'backup_count': 5,
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            },
            'network_scanner': {
                'threads': 50,
                'timeout': 30,
                'nmap_args': '-sS -sV -O --version-intensity 5',
                'top_ports': 1000,
                'ping_timeout': 5,
                'service_detection': True,
                'os_detection': True,
                'vulnerability_scan': True
            },
            'web_recon': {
                'threads': 20,
                'timeout': 30,
                'max_redirects': 5,
                'subdomain_wordlist': 'wordlists/subdomains.txt',
                'directory_wordlist': 'wordlists/directories.txt',
                'user_agents': [
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                ],
                'certificate_transparency': True,
                'dns_bruteforce': True,
                'search_engine_dorking': False,
                'waf_detection': True,
                'technology_detection': True,
                'ssl_analysis': True
            },
            'api_security': {
                'threads': 10,
                'timeout': 30,
                'swagger_endpoints': [
                    '/swagger.json', '/api/swagger.json', '/v1/swagger.json',
                    '/swagger/v1/swagger.json', '/api-docs', '/docs'
                ],
                'openapi_endpoints': [
                    '/openapi.json', '/api/openapi.json', '/openapi/openapi.json'
                ],
                'common_paths': [
                    '/api', '/v1', '/v2', '/v3', '/rest', '/graphql'
                ],
                'authentication_tests': True,
                'authorization_tests': True,
                'input_validation_tests': True,
                'rate_limiting_tests': True
            },
            'cloud_recon': {
                'threads': 10,
                'timeout': 30,
                'aws': {
                    'regions': ['us-east-1', 'us-west-2', 'eu-west-1'],
                    's3_bucket_patterns': [
                        '{target}', '{target}-dev', '{target}-prod',
                        '{target}-backup', '{target}-assets', '{target}-static'
                    ]
                },
                'gcp': {
                    'bucket_patterns': ['{target}', '{target}-storage']
                },
                'azure': {
                    'container_patterns': ['{target}', '{target}-storage']
                }
            },
            'reporting': {
                'templates_dir': 'templates',
                'output_dir': 'reports',
                'formats': ['html', 'json', 'csv', 'markdown'],
                'include_screenshots': False,
                'include_raw_data': True
            }
        }
    
    def _load_config_file(self, config_path: str):
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                file_config = yaml.safe_load(f)
                if file_config and isinstance(file_config, dict):
                    self._deep_merge(self.config_data, file_config)
                else:
                    print(f"Warning: Config file {config_path} is empty or invalid")
        except Exception as e:
            print(f"Warning: Failed to load config file {config_path}: {e}")
    
    def _load_env_overrides(self):
        """Load configuration overrides from environment variables"""
        env_mappings = {
            'UASM_MAX_THREADS': 'general.max_threads',
            'UASM_TIMEOUT': 'general.scan_timeout',
            'UASM_DB_TYPE': 'database.type',
            'UASM_DB_HOST': 'database.host',
            'UASM_LOG_LEVEL': 'logging.level'
        }
        
        for env_var, config_path in env_mappings.items():
            if env_var in os.environ:
                value = os.environ[env_var]
                if config_path.endswith(('threads', 'timeout')):
                    try:
                        value = int(value)
                    except ValueError:
                        continue
                self.set(config_path, value)
    
    def _deep_merge(self, base_dict: Dict, update_dict: Dict):
        """Deep merge two dictionaries"""
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._deep_merge(base_dict[key], value)
            else:
                base_dict[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config_data
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        return self.get(section, {})
    
    def validate(self) -> bool:
        """Validate configuration settings"""
        errors = []
        
        # Validate thread counts
        max_threads = self.get('general.max_threads')
        if not isinstance(max_threads, int) or max_threads < 1 or max_threads > 500:
            errors.append("general.max_threads must be between 1 and 500")
        
        # Validate timeout
        timeout = self.get('general.scan_timeout')
        if not isinstance(timeout, int) or timeout < 60:
            errors.append("general.scan_timeout must be at least 60 seconds")
        
        if errors:
            print("Configuration validation errors:")
            for error in errors:
                print(f"  - {error}")
            return False
        
        return True
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return yaml.dump(self.config_data, default_flow_style=False, indent=2)

