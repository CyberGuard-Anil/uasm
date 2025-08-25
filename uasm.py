#!/usr/bin/env python3
"""
Universal Attack Surface Mapper (UASM) - Main Entry Point
A comprehensive cybersecurity tool for attack surface mapping and vulnerability assessment
"""

import sys
import os
import argparse
import signal
import json
import time
from pathlib import Path
from typing import List, Optional

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from uasm.core.config import Config
from uasm.core.scanner import UASMScanner
from uasm.core.logger import setup_logger, log_scan_start, log_scan_complete
from uasm.core.report_generator import ReportGenerator
from uasm.core.visualizer import UASMVisualizer
from uasm.utils.validators import validate_target


class UASMApp:
    """Main UASM application class"""
    
    def __init__(self):
        self.config = None
        self.logger = None
        self.scanner = None
        self.interrupted = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        self.interrupted = True
        if self.logger:
            self.logger.info(f"\n🛑 Received signal {signum}, stopping scan...")
        if self.scanner:
            self.scanner.stop()
        sys.exit(0)
    
    def setup(self, args):
        """Setup UASM with command line arguments"""
        # Load configuration
        config_path = args.config if args.config else None
        self.config = Config(config_path)
        
        # Override config with command line arguments
        if args.threads:
            self.config.set('general.max_threads', args.threads)
        if args.timeout:
            self.config.set('general.scan_timeout', args.timeout)
        if args.output_dir:
            self.config.set('output.base_dir', args.output_dir)
        
        # Setup logging
        log_config = self.config.get('logging', {})
        if args.verbose:
            log_config['level'] = 'DEBUG'
        if args.log_file:
            log_config['file'] = args.log_file
        
        self.logger = setup_logger('UASM', log_config, args.verbose)
        
        self.logger.info("🛡️  Universal Attack Surface Mapper (UASM) v1.0")
        self.logger.info("=" * 60)
    
    def run_scan(self, args):
        """Run the main scan process"""
        target = args.target
        modules = args.modules or ['network', 'web', 'api', 'cloud']
        
        # Validate target
        if not validate_target(target):
            self.logger.error(f"❌ Invalid target: {target}")
            return False
        
        # Initialize scanner
        self.scanner = UASMScanner(self.config)
        
        try:
            # Configure scanner
            self.scanner.set_target(target)
            self.scanner.set_modules(modules)
            
            if args.threads:
                self.scanner.set_threads(args.threads)
            if args.timeout:
                self.scanner.set_timeout(args.timeout)
            if args.output_dir:
                self.scanner.set_output_dir(args.output_dir)
            
            # Log scan start
            log_scan_start(self.logger, target, modules)
            
            # Run scan
            start_time = time.time()
            results = self.scanner.run()
            duration = time.time() - start_time
            
            # Log scan completion
            total_findings = len(results.get('vulnerabilities', [])) + len(results.get('findings', []))
            log_scan_complete(self.logger, duration, total_findings)
            
            # Generate reports if requested
            if args.report_format and args.report_format != 'none':
                self._generate_reports(results, args)
            
            # Generate visualizations if requested
            if args.visualize:
                self._generate_visualizations(results, args)
            
            # Print summary
            self._print_summary(results)
            
            return True
            
        except KeyboardInterrupt:
            self.logger.info("\n🛑 Scan interrupted by user")
            return False
        except Exception as e:
            self.logger.error(f"❌ Scan failed: {str(e)}")
            if args.verbose:
                import traceback
                self.logger.debug(traceback.format_exc())
            return False
    
    def _generate_reports(self, results, args):
        """Generate scan reports"""
        try:
            self.logger.info("📄 Generating reports...")
            
            report_gen = ReportGenerator(self.config)
            formats = args.report_format.split(',') if isinstance(args.report_format, str) else [args.report_format]
            
            for format_name in formats:
                format_name = format_name.strip()
                if format_name != 'none':
                    output_path = None
                    if args.report_output:
                        output_path = f"{args.report_output}.{format_name}"
                    
                    report_path = report_gen.generate_report(results, format_name, output_path)
                    self.logger.info(f"✅ {format_name.upper()} report saved: {report_path}")
                    
        except Exception as e:
            self.logger.error(f"Failed to generate reports: {str(e)}")
    
    def _generate_visualizations(self, results, args):
        """Generate visualizations"""
        try:
            self.logger.info("📊 Generating visualizations...")
            
            visualizer = UASMVisualizer(self.config)
            
            # Create output directory for visualizations
            viz_dir = Path(args.output_dir or '.') / 'visualizations'
            viz_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate dashboard assets
            assets = visualizer.generate_dashboard_assets(results, str(viz_dir))
            
            for asset_name, asset_path in assets.items():
                self.logger.info(f"✅ Generated {asset_name}: {asset_path}")
            
            # Export graph data for web visualization
            graph_data_path = viz_dir / 'graph_data.json'
            visualizer.export_graph_data(results, str(graph_data_path))
            self.logger.info(f"✅ Graph data exported: {graph_data_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to generate visualizations: {str(e)}")
    
    def _print_summary(self, results):
        """Print scan summary"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info("📊 SCAN SUMMARY")
        self.logger.info("=" * 60)
        
        # Basic statistics
        hosts = results.get('hosts', [])
        subdomains = results.get('subdomains', [])
        vulnerabilities = results.get('vulnerabilities', [])
        findings = results.get('findings', [])
        
        self.logger.info(f"🖥️  Hosts discovered: {len(hosts)}")
        self.logger.info(f"🌐 Subdomains found: {len(subdomains)}")
        self.logger.info(f"🚨 Vulnerabilities: {len(vulnerabilities)}")
        self.logger.info(f"📋 Total findings: {len(findings)}")
        
        # Vulnerability breakdown
        if vulnerabilities:
            severity_counts = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'unknown').title()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            self.logger.info("\n🚨 Vulnerability Breakdown:")
            for severity, count in sorted(severity_counts.items()):
                icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
                self.logger.info(f"   {icon} {severity}: {count}")
        
        # Top findings
        if findings:
            self.logger.info("\n📋 Top Findings:")
            for i, finding in enumerate(findings[:5], 1):
                title = finding.get('title', 'Unknown')[:60]
                category = finding.get('category', 'unknown').title()
                self.logger.info(f"   {i}. [{category}] {title}")
        
        self.logger.info("\n" + "=" * 60)


def create_arg_parser():
    """Create command line argument parser"""
    
    epilog_text = """
Examples:
  uasm.py -t example.com                                    # Basic scan
  uasm.py -t example.com -m network web                    # Scan with specific modules
  uasm.py -t example.com -r html,json -o ./results         # Generate reports
  uasm.py -t 192.168.1.0/24 -T 100 --timeout 1800         # Network scan with custom settings
  uasm.py -t example.com --visualize -v                    # Full scan with visualizations
"""
    
    parser = argparse.ArgumentParser(
        description="Universal Attack Surface Mapper (UASM) - Comprehensive Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog_text
    )
    
    # Target specification
    parser.add_argument('-t', '--target', required=True,
                       help='Target to scan (domain, IP, CIDR, or URL)')
    
    # Module selection
    parser.add_argument('-m', '--modules', nargs='+',
                       choices=['network', 'web', 'api', 'cloud'],
                       help='Scanner modules to run (default: all)')
    
    # Scanning options
    parser.add_argument('-T', '--threads', type=int, metavar='N',
                       help='Number of threads to use (default: 50)')
    parser.add_argument('--timeout', type=int, metavar='SECONDS',
                       help='Scan timeout in seconds (default: 3600)')
    
    # Output options
    parser.add_argument('-o', '--output-dir', metavar='DIR',
                       help='Output directory for results')
    parser.add_argument('-r', '--report-format',
                       choices=['html', 'json', 'csv', 'markdown', 'pdf', 'none'],
                       default='html',
                       help='Report format (default: html)')
    parser.add_argument('--report-output', metavar='PATH',
                       help='Custom report output path (without extension)')
    parser.add_argument('--visualize', action='store_true',
                       help='Generate visualizations')
    
    # Configuration
    parser.add_argument('-c', '--config', metavar='FILE',
                       help='Configuration file path')
    
    # Logging
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-l', '--log-file', metavar='FILE',
                       help='Log file path')
    
    # Information
    parser.add_argument('--version', action='version', version='UASM v1.0')
    
    return parser


def check_requirements():
    """Check if required dependencies are installed"""
    required_modules = [
        'requests', 
        'jinja2',
        'matplotlib',
        'networkx',
        'sqlalchemy',
        'yaml'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    # Check for optional modules
    optional_modules = {
        'python_nmap': 'nmap',
        'dnspython': 'dns'
    }
    
    for package, import_name in optional_modules.items():
        try:
            __import__(import_name)
        except ImportError:
            print(f"⚠️  Optional dependency missing: {package}")
    
    if missing_modules:
        print(f"❌ Missing required dependencies: {', '.join(missing_modules)}")
        print("Please install them using: pip install -r requirements.txt")
        return False
    
    return True


def main():
    """Main entry point"""
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Parse arguments
    parser = create_arg_parser()
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Initialize and run UASM
    app = UASMApp()
    
    try:
        app.setup(args)
        success = app.run_scan(args)
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()

