"""
Main Scanner Engine for UASM
Orchestrates all scanner modules and manages scan lifecycle
"""

import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from uasm.core.logger import create_module_logger, log_module_start, log_module_complete
from uasm.core.database import Database
from uasm.modules.network_scanner import NetworkScanner
from uasm.modules.web_recon import WebRecon
from uasm.modules.api_security import APISecurityScanner
from uasm.modules.cloud_recon import CloudRecon
from uasm.modules.correlator import ResultsCorrelator
from uasm.utils.helpers import generate_output_dir, clean_domain


class UASMScanner:
    """Main scanner engine that orchestrates all modules"""
    
    def __init__(self, config):
        """Initialize the main scanner"""
        self.config = config
        self.logger = create_module_logger('UASMScanner')
        
        # Scanner configuration
        self.target = None
        self.modules = ['network', 'web', 'api', 'cloud']
        self.threads = config.get('general.max_threads', 50)
        self.timeout = config.get('general.scan_timeout', 3600)
        self.output_dir = None
        
        # Scan state
        self.scan_id = None
        self.start_time = None
        self.end_time = None
        self.results = {}
        self.running = False
        self._stop_event = threading.Event()
        
        # Initialize database if configured
        self.db = None
        if config.get('database.type'):
            try:
                self.db = Database(config)
            except Exception as e:
                self.logger.warning(f"Database initialization failed: {str(e)}")
        
        # Initialize modules
        self.scanner_modules = {}
        self.correlator = ResultsCorrelator(config)
        
        self.logger.info("UASM Scanner initialized")
    
    def set_target(self, target: str):
        """Set scan target"""
        self.target = target
        self.logger.info(f"Target set: {target}")
    
    def set_modules(self, modules: List[str]):
        """Set modules to run"""
        valid_modules = ['network', 'web', 'api', 'cloud']
        self.modules = [m for m in modules if m in valid_modules]
        self.logger.info(f"Modules set: {', '.join(self.modules)}")
    
    def set_threads(self, threads: int):
        """Set thread count"""
        self.threads = max(1, min(threads, 500))
        self.logger.info(f"Thread count set: {self.threads}")
    
    def set_timeout(self, timeout: int):
        """Set scan timeout"""
        self.timeout = max(60, timeout)
        self.logger.info(f"Timeout set: {self.timeout} seconds")
    
    def set_output_dir(self, output_dir: str):
        """Set output directory"""
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self.logger.info(f"Output directory set: {output_dir}")
    
    def run(self) -> Dict[str, Any]:
        """Run the complete scan process"""
        if not self.target:
            raise ValueError("Target must be set before running scan")
        
        self.running = True
        self._stop_event.clear()
        
        # Initialize scan
        self.start_time = datetime.now()
        self.scan_id = f"scan_{int(time.time())}"
        
        if not self.output_dir:
            self.output_dir = generate_output_dir(self.target)
            Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"🚀 Starting scan {self.scan_id}")
        self.logger.info(f"📁 Output directory: {self.output_dir}")
        
        try:
            # Initialize scanner modules
            self._initialize_modules()
            
            # Run scanner modules
            module_results = self._run_modules()
            
            # Correlate results
            correlated_results = self._correlate_results(module_results)
            
            # Compile final results
            self.results = self._compile_results(module_results, correlated_results)
            
            # Save to database if available
            if self.db:
                try:
                    db_scan_id = self.db.save_scan_result(self.results)
                    self.logger.info(f"Results saved to database: {db_scan_id}")
                except Exception as e:
                    self.logger.warning(f"Failed to save to database: {str(e)}")
            
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            
            self.logger.info(f"✅ Scan completed in {duration:.2f} seconds")
            
            return self.results
            
        except Exception as e:
            self.logger.error(f"❌ Scan failed: {str(e)}")
            raise
        finally:
            self.running = False
    
    def _initialize_modules(self):
        """Initialize scanner modules"""
        self.logger.info("🔧 Initializing scanner modules...")
        
        for module_name in self.modules:
            try:
                if module_name == 'network':
                    self.scanner_modules['network'] = NetworkScanner(
                        self.config, self.target, self.db
                    )
                elif module_name == 'web':
                    self.scanner_modules['web'] = WebRecon(
                        self.config, self.target, self.db
                    )
                elif module_name == 'api':
                    self.scanner_modules['api'] = APISecurityScanner(
                        self.config, self.target, self.db
                    )
                elif module_name == 'cloud':
                    self.scanner_modules['cloud'] = CloudRecon(
                        self.config, self.target, self.db
                    )
                
                # Set output directory for module
                if hasattr(self.scanner_modules[module_name], 'set_output_dir'):
                    module_output = Path(self.output_dir) / module_name
                    self.scanner_modules[module_name].set_output_dir(str(module_output))
                
                self.logger.info(f"✅ {module_name.title()} module initialized")
                
            except Exception as e:
                self.logger.error(f"❌ Failed to initialize {module_name} module: {str(e)}")
                # Remove failed module from execution list
                if module_name in self.scanner_modules:
                    del self.scanner_modules[module_name]
    
    def _run_modules(self) -> Dict[str, Any]:
        """Run all scanner modules"""
        self.logger.info("🔍 Running scanner modules...")
        
        module_results = {}
        
        # Run modules sequentially for now (can be parallelized later)
        for module_name, module in self.scanner_modules.items():
            if self._stop_event.is_set():
                self.logger.info("🛑 Scan stopped by user")
                break
            
            try:
                log_module_start(self.logger, module_name, self.target)
                
                start_time = time.time()
                results = module.run()
                duration = time.time() - start_time
                
                module_results[module_name] = results
                
                findings_count = (len(results.get('vulnerabilities', [])) + 
                                len(results.get('findings', [])))
                
                log_module_complete(self.logger, module_name, findings_count, duration)
                
            except Exception as e:
                self.logger.error(f"❌ {module_name} module failed: {str(e)}")
                module_results[module_name] = {
                    'error': str(e),
                    'vulnerabilities': [],
                    'findings': [],
                    'statistics': {}
                }
        
        return module_results
    
    def _correlate_results(self, module_results: Dict[str, Any]) -> Dict[str, Any]:
        """Correlate results across modules"""
        self.logger.info("🔗 Correlating scan results...")
        
        try:
            # Extract data for correlation
            network_hosts = module_results.get('network', {}).get('hosts', [])
            web_subdomains = module_results.get('web', {}).get('subdomains', [])
            all_vulnerabilities = []
            all_findings = []
            
            # Collect all vulnerabilities and findings
            for module_name, results in module_results.items():
                vulnerabilities = results.get('vulnerabilities', [])
                findings = results.get('findings', [])
                
                # Add module info to each item
                for vuln in vulnerabilities:
                    vuln['module'] = module_name
                    all_vulnerabilities.append(vuln)
                
                for finding in findings:
                    finding['module'] = module_name
                    all_findings.append(finding)
            
            # Run correlation analysis
            correlations = {}
            
            # Network-Web correlation
            if network_hosts and web_subdomains:
                correlations['network_web'] = self.correlator.correlate_network_web(
                    network_hosts, web_subdomains
                )
            
            # Find API endpoints from web data
            if web_subdomains:
                correlations['api_endpoints'] = self.correlator.find_api_endpoints(
                    web_subdomains
                )
            
            # Enrich vulnerabilities with context
            enriched_vulns = self.correlator.enrich_vulnerabilities(
                all_vulnerabilities, network_hosts, web_subdomains
            )
            
            # Generate attack paths
            attack_paths = self.correlator.generate_attack_paths(
                network_hosts, web_subdomains, all_vulnerabilities
            )
            
            # Prioritize all findings
            prioritized_findings = self.correlator.prioritize_findings(all_findings)
            
            return {
                'correlations': correlations,
                'enriched_vulnerabilities': enriched_vulns,
                'attack_paths': attack_paths,
                'prioritized_findings': prioritized_findings
            }
            
        except Exception as e:
            self.logger.error(f"❌ Correlation failed: {str(e)}")
            return {}
    
    def _compile_results(self, module_results: Dict[str, Any], 
                        correlated_results: Dict[str, Any]) -> Dict[str, Any]:
        """Compile final scan results"""
        self.logger.info("📊 Compiling final results...")
        
        # Aggregate all data
        all_hosts = []
        all_subdomains = []
        all_vulnerabilities = []
        all_findings = []
        combined_statistics = {}
        
        # Collect data from all modules
        for module_name, results in module_results.items():
            if 'error' in results:
                continue
                
            all_hosts.extend(results.get('hosts', []))
            all_subdomains.extend(results.get('subdomains', []))
            all_vulnerabilities.extend(results.get('vulnerabilities', []))
            all_findings.extend(results.get('findings', []))
            
            # Merge statistics
            module_stats = results.get('statistics', {})
            for key, value in module_stats.items():
                if isinstance(value, (int, float)):
                    combined_statistics[f"{module_name}_{key}"] = value
                else:
                    combined_statistics[f"{module_name}_{key}"] = value
        
        # Use enriched vulnerabilities if available
        if correlated_results.get('enriched_vulnerabilities'):
            all_vulnerabilities = correlated_results['enriched_vulnerabilities']
        
        # Use prioritized findings if available
        if correlated_results.get('prioritized_findings'):
            all_findings = correlated_results['prioritized_findings']
        
        # Calculate overall statistics
        overall_stats = self._calculate_overall_statistics(
            all_hosts, all_subdomains, all_vulnerabilities, all_findings
        )
        combined_statistics.update(overall_stats)
        
        # Compile final results
        final_results = {
            'scan_info': {
                'scan_id': self.scan_id,
                'target': self.target,
                'modules': self.modules,
                'start_time': self.start_time.isoformat(),
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'duration': (self.end_time - self.start_time).total_seconds() if self.end_time else None,
                'output_dir': self.output_dir
            },
            'hosts': all_hosts,
            'subdomains': all_subdomains,
            'vulnerabilities': all_vulnerabilities,
            'findings': all_findings,
            'statistics': combined_statistics,
            'correlations': correlated_results.get('correlations', {}),
            'attack_paths': correlated_results.get('attack_paths', []),
            'module_results': module_results
        }
        
        return final_results
    
    def _calculate_overall_statistics(self, hosts: List, subdomains: List, 
                                    vulnerabilities: List, findings: List) -> Dict[str, Any]:
        """Calculate overall scan statistics"""
        stats = {
            'total_hosts': len(hosts),
            'total_subdomains': len(subdomains),
            'total_vulnerabilities': len(vulnerabilities),
            'total_findings': len(findings),
            'vulnerability_severity_distribution': {},
            'finding_category_distribution': {},
            'risk_score': 0.0
        }
        
        # Vulnerability severity distribution
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            stats['vulnerability_severity_distribution'][severity] = \
                stats['vulnerability_severity_distribution'].get(severity, 0) + 1
        
        # Finding category distribution
        for finding in findings:
            category = finding.get('category', 'unknown')
            stats['finding_category_distribution'][category] = \
                stats['finding_category_distribution'].get(category, 0) + 1
        
        # Calculate risk score
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        total_risk = 0
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info')
            cvss_score = vuln.get('cvss_score', 0)
            
            # Use CVSS score if available, otherwise use severity weight
            if cvss_score > 0:
                total_risk += cvss_score
            else:
                total_risk += severity_weights.get(severity, 1)
        
        # Normalize risk score (0-100)
        if vulnerabilities:
            max_possible_risk = len(vulnerabilities) * 10
            stats['risk_score'] = min((total_risk / max_possible_risk) * 100, 100)
        
        return stats
    
    def stop(self):
        """Stop the scan"""
        self.logger.info("🛑 Stopping scan...")
        self._stop_event.set()
        
        # Stop individual modules
        for module in self.scanner_modules.values():
            if hasattr(module, 'stop'):
                try:
                    module.stop()
                except Exception as e:
                    self.logger.debug(f"Error stopping module: {str(e)}")
        
        self.running = False
    
    def get_status(self) -> Dict[str, Any]:
        """Get current scan status"""
        status = {
            'running': self.running,
            'scan_id': self.scan_id,
            'target': self.target,
            'modules': self.modules,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'output_dir': self.output_dir
        }
        
        if self.start_time:
            elapsed = (datetime.now() - self.start_time).total_seconds()
            status['elapsed_time'] = elapsed
        
        return status
    
    def cleanup(self):
        """Cleanup resources"""
        self.logger.info("🧹 Cleaning up scanner resources...")
        
        # Stop scan if running
        if self.running:
            self.stop()
        
        # Close database connection
        if self.db:
            try:
                self.db.close()
            except Exception as e:
                self.logger.debug(f"Error closing database: {str(e)}")
        
        # Clear module references
        self.scanner_modules.clear()
        
        self.logger.info("✅ Cleanup completed")

