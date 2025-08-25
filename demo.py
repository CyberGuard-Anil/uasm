#!/usr/bin/env python3
"""
UASM Demo Script
Generates sample scan results and demonstrates report generation
"""

import json
import time
from datetime import datetime
from pathlib import Path

def generate_sample_scan_results():
    """Generate sample scan results for demonstration"""
    
    sample_results = {
        "scan_info": {
            "scan_id": f"demo_scan_{int(time.time())}",
            "target": "demo.example.com",
            "modules": ["network", "web", "api", "cloud"],
            "start_time": datetime.now().isoformat(),
            "end_time": datetime.now().isoformat(),
            "duration": 245.67,
            "output_dir": "./demo_results"
        },
        "hosts": [
            {
                "ip_address": "192.168.1.100",
                "hostname": "demo.example.com",
                "status": "up",
                "ports": [
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "ssh",
                        "banner": "SSH-2.0-OpenSSH_8.2",
                        "product": "OpenSSH",
                        "version": "8.2"
                    },
                    {
                        "port": 80,
                        "protocol": "tcp", 
                        "state": "open",
                        "service": "http",
                        "banner": "Apache/2.4.41",
                        "product": "Apache",
                        "version": "2.4.41"
                    },
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "state": "open", 
                        "service": "https",
                        "banner": "Apache/2.4.41 SSL",
                        "product": "Apache",
                        "version": "2.4.41"
                    }
                ],
                "os_info": {
                    "name": "Linux 5.4.0",
                    "family": "Linux",
                    "accuracy": "95%"
                }
            }
        ],
        "subdomains": [
            {
                "subdomain": "www.demo.example.com",
                "ip_address": "192.168.1.100",
                "status_code": 200,
                "title": "Demo Website - Home Page",
                "server": "Apache/2.4.41 (Ubuntu)",
                "technologies": ["Apache", "PHP", "MySQL"],
                "ssl_info": {
                    "version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "subject": {"CN": "demo.example.com"},
                    "issuer": {"CN": "Let's Encrypt Authority X3"},
                    "not_before": "2024-01-01T00:00:00Z",
                    "not_after": "2024-04-01T00:00:00Z"
                }
            },
            {
                "subdomain": "api.demo.example.com",
                "ip_address": "192.168.1.100", 
                "status_code": 401,
                "title": "API Gateway",
                "server": "nginx/1.18.0",
                "technologies": ["nginx", "Node.js", "Express"]
            },
            {
                "subdomain": "admin.demo.example.com",
                "ip_address": "192.168.1.100",
                "status_code": 403,
                "title": "Admin Panel - Access Denied",
                "server": "Apache/2.4.41 (Ubuntu)",
                "technologies": ["Apache", "PHP"]
            }
        ],
        "vulnerabilities": [
            {
                "title": "Outdated SSH Version",
                "description": "SSH server is running an outdated version that may contain known vulnerabilities",
                "severity": "medium",
                "cvss_score": 5.3,
                "target_host": "192.168.1.100",
                "target_port": 22,
                "remediation": "Update SSH server to the latest version",
                "cve_id": "CVE-2021-41617",
                "cwe_id": "CWE-295",
                "module": "network",
                "discovered_at": time.time()
            },
            {
                "title": "Missing Security Headers",
                "description": "Web application is missing critical security headers including X-Frame-Options and CSP",
                "severity": "low",
                "cvss_score": 2.0,
                "target_url": "https://www.demo.example.com",
                "remediation": "Implement proper security headers in web server configuration",
                "cwe_id": "CWE-16",
                "module": "web",
                "discovered_at": time.time()
            },
            {
                "title": "Weak TLS Configuration",
                "description": "Server supports TLS 1.1 which is deprecated and potentially vulnerable",
                "severity": "medium",
                "cvss_score": 4.3,
                "target_url": "https://demo.example.com",
                "remediation": "Disable TLS 1.0 and 1.1, enforce TLS 1.2 or higher",
                "cwe_id": "CWE-326",
                "module": "web",
                "discovered_at": time.time()
            },
            {
                "title": "Admin Panel Accessible",
                "description": "Administrative interface is accessible from the internet",
                "severity": "high",
                "cvss_score": 7.5,
                "target_url": "https://admin.demo.example.com",
                "remediation": "Restrict admin panel access to trusted IP addresses or VPN",
                "cwe_id": "CWE-284",
                "module": "web",
                "discovered_at": time.time()
            },
            {
                "title": "API Endpoint Without Authentication",
                "description": "API endpoint discovered that does not require authentication",
                "severity": "medium",
                "cvss_score": 6.1,
                "target_url": "https://api.demo.example.com/v1/users",
                "remediation": "Implement proper authentication for all API endpoints",
                "cwe_id": "CWE-306",
                "module": "api",
                "discovered_at": time.time()
            }
        ],
        "findings": [
            {
                "category": "network",
                "subcategory": "host_discovery",
                "title": "Live Host Discovered: 192.168.1.100",
                "description": "Host 192.168.1.100 responded to ping probes",
                "severity": "info",
                "target": "192.168.1.100",
                "module": "network",
                "discovered_at": time.time()
            },
            {
                "category": "web",
                "subcategory": "subdomain_discovery",
                "title": "Subdomain Found: www.demo.example.com",
                "description": "Subdomain discovered via DNS bruteforce",
                "severity": "info",
                "target": "www.demo.example.com",
                "module": "web",
                "discovered_at": time.time()
            },
            {
                "category": "web",
                "subcategory": "technology_detection",
                "title": "Technology Detected: Apache",
                "description": "Web technology Apache detected on 2 subdomain(s)",
                "severity": "info",
                "target": "www.demo.example.com, admin.demo.example.com",
                "module": "web",
                "discovered_at": time.time()
            },
            {
                "category": "api",
                "subcategory": "endpoint_discovery",
                "title": "API Endpoint Found: /v1",
                "description": "API endpoint discovered at https://api.demo.example.com/v1",
                "severity": "info",
                "target": "https://api.demo.example.com/v1",
                "module": "api",
                "discovered_at": time.time()
            }
        ],
        "statistics": {
            "total_hosts": 1,
            "total_subdomains": 3,
            "total_vulnerabilities": 5,
            "total_findings": 4,
            "vulnerability_severity_distribution": {
                "critical": 0,
                "high": 1,
                "medium": 3,
                "low": 1,
                "info": 0
            },
            "risk_score": 35.2,
            "network_total_hosts_scanned": 1,
            "network_total_open_ports": 3,
            "web_total_subdomains": 3,
            "web_ssl_enabled_subdomains": 3,
            "api_total_api_endpoints": 1,
            "cloud_total_cloud_assets": 0
        },
        "correlations": {
            "network_web": [
                {
                    "subdomain": "www.demo.example.com",
                    "ip_address": "192.168.1.100",
                    "hostname": "demo.example.com",
                    "open_ports": [22, 80, 443],
                    "web_status": 200,
                    "web_server": "Apache/2.4.41 (Ubuntu)",
                    "confidence": 1.0
                }
            ]
        },
        "attack_paths": [
            {
                "path_id": "path_1",
                "entry_point": {
                    "type": "web",
                    "target": "admin.demo.example.com",
                    "ip": "192.168.1.100",
                    "vulnerabilities": ["Admin Panel Accessible"]
                },
                "lateral_movement": {
                    "type": "network",
                    "target": "192.168.1.100",
                    "open_ports": [22, 80, 443],
                    "vulnerabilities": ["Outdated SSH Version"]
                },
                "severity": 7.5,
                "complexity": "Medium",
                "steps": [
                    {
                        "step": 1,
                        "phase": "Initial Access",
                        "action": "Exploit Admin Panel Accessible",
                        "target": "https://admin.demo.example.com",
                        "impact": "Web application compromise"
                    },
                    {
                        "step": 2,
                        "phase": "Lateral Movement", 
                        "action": "Exploit Outdated SSH Version",
                        "target": "192.168.1.100",
                        "impact": "System compromise"
                    }
                ]
            }
        ]
    }
    
    return sample_results

def main():
    """Main demo function"""
    print("🛡️  UASM Demo Script")
    print("=" * 50)
    
    # Generate sample results
    print("📊 Generating sample scan results...")
    results = generate_sample_scan_results()
    
    # Save sample results to file
    output_file = "sample_scan_results.json"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"✅ Sample results saved to: {output_file}")
    except Exception as e:
        print(f"❌ Failed to save sample results: {e}")
        return
    
    # Try to generate a report using UASM
    try:
        from uasm.core.config import Config
        from uasm.core.report_generator import ReportGenerator
        
        print("📄 Generating sample report...")
        
        # Initialize config and report generator
        config = Config()
        generator = ReportGenerator(config)
        
        # Generate HTML report
        html_report = generator.generate_report(results, 'html')
        print(f"✅ HTML report generated: {html_report}")
        
        # Generate JSON report
        json_report = generator.generate_report(results, 'json')
        print(f"✅ JSON report generated: {json_report}")
        
        print("\n🎉 Demo completed successfully!")
        print("📋 Summary:")
        print(f"   - Target: {results['scan_info']['target']}")
        print(f"   - Hosts: {results['statistics']['total_hosts']}")
        print(f"   - Subdomains: {results['statistics']['total_subdomains']}")
        print(f"   - Vulnerabilities: {results['statistics']['total_vulnerabilities']}")
        print(f"   - Risk Score: {results['statistics']['risk_score']}")
        
    except ImportError as e:
        print(f"⚠️  Could not import UASM modules: {e}")
        print("📄 Sample data generated, but reports require full UASM installation")
    except Exception as e:
        print(f"❌ Demo failed: {e}")

if __name__ == "__main__":
    main()

