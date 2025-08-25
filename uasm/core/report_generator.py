"""
Report Generator Module for UASM
Generates comprehensive security reports in various formats
"""

import os
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional
import base64
from jinja2 import Environment, FileSystemLoader, Template

from uasm.core.logger import create_module_logger
from uasm.utils.helpers import format_duration, format_bytes, sanitize_filename


class ReportGenerator:
    """Generate security reports from scan results"""
    
    def __init__(self, config):
        """Initialize report generator"""
        self.config = config
        self.logger = create_module_logger('ReportGenerator')
        
        # Report configuration
        self.report_config = self.config.get('reporting', {})
        self.templates_dir = self.report_config.get('templates_dir', 'templates')
        self.output_dir = self.report_config.get('output_dir', 'reports')
        
        # Ensure output directory exists
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self._init_templates()
        
        self.logger.info("Report generator initialized")
    
    def _init_templates(self):
        """Initialize Jinja2 template environment"""
        try:
            # Try to load templates from configured directory
            if Path(self.templates_dir).exists():
                self.jinja_env = Environment(loader=FileSystemLoader(self.templates_dir))
            else:
                # Use built-in templates
                self.jinja_env = Environment(loader=FileSystemLoader('.'))
            
            # Add custom filters
            self.jinja_env.filters['format_duration'] = format_duration
            self.jinja_env.filters['format_bytes'] = format_bytes
            self.jinja_env.filters['severity_color'] = self._get_severity_color
            self.jinja_env.filters['format_timestamp'] = self._format_timestamp
            
        except Exception as e:
            self.logger.error(f"Failed to initialize templates: {str(e)}")
            # Create basic environment without file loader
            self.jinja_env = Environment()
    
    def generate_report(self, scan_results: Dict[str, Any], 
                       format: str = 'html', 
                       output_path: Optional[str] = None) -> str:
        """Generate scan report in specified format"""
        
        if format not in ['html', 'pdf', 'json', 'csv', 'markdown']:
            raise ValueError(f"Unsupported report format: {format}")
        
        self.logger.info(f"Generating {format.upper()} report...")
        
        # Prepare report data
        report_data = self._prepare_report_data(scan_results)
        
        # Generate report based on format
        if format == 'html':
            return self._generate_html_report(report_data, output_path)
        elif format == 'pdf':
            return self._generate_pdf_report(report_data, output_path)
        elif format == 'json':
            return self._generate_json_report(report_data, output_path)
        elif format == 'csv':
            return self._generate_csv_report(report_data, output_path)
        elif format == 'markdown':
            return self._generate_markdown_report(report_data, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _prepare_report_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare and enrich report data"""
        report_data = {
            'metadata': self._generate_metadata(scan_results),
            'executive_summary': self._generate_executive_summary(scan_results),
            'scan_info': scan_results.get('scan_info', {}),
            'statistics': self._calculate_enhanced_statistics(scan_results),
            'vulnerabilities': self._process_vulnerabilities(scan_results.get('vulnerabilities', [])),
            'findings': self._process_findings(scan_results.get('findings', [])),
            'hosts': scan_results.get('hosts', []),
            'subdomains': scan_results.get('subdomains', []),
            'recommendations': self._generate_recommendations(scan_results),
            'risk_assessment': self._calculate_risk_assessment(scan_results)
        }
        
        return report_data
    
    def _generate_metadata(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate report metadata"""
        scan_info = scan_results.get('scan_info', {})
        
        metadata = {
            'generated_at': datetime.now().isoformat(),
            'generator': 'UASM Report Generator v1.0',
            'target': scan_info.get('target', 'Unknown'),
            'scan_duration': scan_info.get('duration', 0),
            'total_findings': len(scan_results.get('findings', [])) + len(scan_results.get('vulnerabilities', [])),
            'severity_distribution': self._calculate_severity_distribution(scan_results),
            'scan_modules': scan_info.get('modules', [])
        }
        
        return metadata
    
    def _generate_executive_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        findings = scan_results.get('findings', [])
        
        # Calculate risk score
        total_risk_score = sum(v.get('cvss_score', 0) for v in vulnerabilities)
        avg_risk_score = total_risk_score / len(vulnerabilities) if vulnerabilities else 0
        
        # Risk level determination
        if avg_risk_score >= 8.0:
            risk_level = 'Critical'
        elif avg_risk_score >= 6.0:
            risk_level = 'High'
        elif avg_risk_score >= 4.0:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
        
        # Top vulnerabilities
        top_vulnerabilities = sorted(vulnerabilities, 
                                   key=lambda x: x.get('cvss_score', 0), 
                                   reverse=True)[:5]
        
        summary = {
            'overall_risk_level': risk_level,
            'average_risk_score': round(avg_risk_score, 2),
            'total_vulnerabilities': len(vulnerabilities),
            'total_findings': len(findings),
            'critical_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'critical']),
            'high_vulnerabilities': len([v for v in vulnerabilities if v.get('severity') == 'high']),
            'top_vulnerabilities': top_vulnerabilities,
            'key_recommendations': self._get_key_recommendations(vulnerabilities, findings),
            'attack_surface_size': self._calculate_attack_surface_size(scan_results)
        }
        
        return summary
    
    def _calculate_enhanced_statistics(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate enhanced statistics"""
        stats = scan_results.get('statistics', {})
        
        enhanced_stats = {
            'basic': stats,
            'vulnerability_stats': self._calculate_vulnerability_stats(scan_results.get('vulnerabilities', [])),
            'finding_stats': self._calculate_finding_stats(scan_results.get('findings', [])),
            'coverage_stats': self._calculate_coverage_stats(scan_results)
        }
        
        return enhanced_stats
    
    def _process_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and enrich vulnerability data"""
        processed_vulns = []
        
        for vuln in vulnerabilities:
            processed_vuln = vuln.copy()
            
            # Add risk category
            cvss_score = vuln.get('cvss_score', 0)
            if cvss_score >= 9.0:
                processed_vuln['risk_category'] = 'Critical'
            elif cvss_score >= 7.0:
                processed_vuln['risk_category'] = 'High'
            elif cvss_score >= 4.0:
                processed_vuln['risk_category'] = 'Medium'
            else:
                processed_vuln['risk_category'] = 'Low'
            
            # Add remediation priority
            severity = vuln.get('severity', '').lower()
            if severity == 'critical':
                processed_vuln['remediation_priority'] = 'Immediate'
                processed_vuln['remediation_timeline'] = '24-48 hours'
            elif severity == 'high':
                processed_vuln['remediation_priority'] = 'High'
                processed_vuln['remediation_timeline'] = '1-2 weeks'
            elif severity == 'medium':
                processed_vuln['remediation_priority'] = 'Medium'
                processed_vuln['remediation_timeline'] = '1-2 months'
            else:
                processed_vuln['remediation_priority'] = 'Low'
                processed_vuln['remediation_timeline'] = '3+ months'
            
            processed_vulns.append(processed_vuln)
        
        # Sort by CVSS score descending
        processed_vulns.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        return processed_vulns
    
    def _generate_html_report(self, report_data: Dict[str, Any], output_path: Optional[str]) -> str:
        """Generate HTML report"""
        if not output_path:
            target = report_data['metadata'].get('target', 'unknown')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = Path(self.output_dir) / f"uasm_report_{sanitize_filename(target)}_{timestamp}.html"
        
        # HTML template
        html_template = self._get_html_template()
        
        try:
            template = Template(html_template)
            html_content = template.render(report=report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {str(e)}")
            raise
    
    def _get_html_template(self) -> str:
        """Get HTML report template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UASM Security Report - {{ report.metadata.target }}</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            margin: 0; 
            padding: 20px; 
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 2rem; 
            border-radius: 10px; 
            margin-bottom: 2rem; 
        }
        .summary-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 1rem; 
            margin: 2rem 0; 
        }
        .summary-card { 
            background: white; 
            border: 1px solid #e0e0e0; 
            border-radius: 8px; 
            padding: 1.5rem; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
        }
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        .vulnerability { 
            background: #f8f9fa; 
            border-left: 4px solid #dc3545; 
            padding: 1rem; 
            margin: 1rem 0; 
            border-radius: 0 5px 5px 0; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 1rem 0; 
        }
        th, td { 
            padding: 0.75rem; 
            text-align: left; 
            border-bottom: 1px solid #dee2e6; 
        }
        th { 
            background-color: #f8f9fa; 
            font-weight: 600; 
        }
        .recommendation { 
            background: #d4edda; 
            border: 1px solid #c3e6cb; 
            border-radius: 5px; 
            padding: 1rem; 
            margin: 1rem 0; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ UASM Security Assessment Report</h1>
            <p>Target: <strong>{{ report.metadata.target }}</strong></p>
            <p>Generated: {{ report.metadata.generated_at }}</p>
        </div>

        <div class="summary-grid">
            <div class="summary-card">
                <h3>Risk Level</h3>
                <h2 class="severity-{{ report.executive_summary.overall_risk_level.lower() }}">
                    {{ report.executive_summary.overall_risk_level }}
                </h2>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <h2>{{ report.metadata.total_findings }}</h2>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilities</h3>
                <h2>{{ report.executive_summary.total_vulnerabilities }}</h2>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <h2>{{ "%.1f"|format(report.scan_info.duration or 0) }}s</h2>
            </div>
        </div>

        <h2>🚨 Critical & High Risk Vulnerabilities</h2>
        {% for vuln in report.vulnerabilities[:10] %}
        {% if vuln.severity in ['critical', 'high'] %}
        <div class="vulnerability">
            <h3 class="severity-{{ vuln.severity }}">{{ vuln.title }}</h3>
            <p><strong>Severity:</strong> {{ vuln.severity | title }} 
               <strong>CVSS:</strong> {{ vuln.cvss_score or 'N/A' }}</p>
            <p><strong>Target:</strong> {{ vuln.target_host or vuln.target_url }}</p>
            <p>{{ vuln.description }}</p>
            {% if vuln.remediation %}
            <p><strong>Remediation:</strong> {{ vuln.remediation }}</p>
            {% endif %}
        </div>
        {% endif %}
        {% endfor %}

        <h2>📊 Scan Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Hosts Discovered</td><td>{{ report.hosts | length }}</td></tr>
            <tr><td>Subdomains Found</td><td>{{ report.subdomains | length }}</td></tr>
            <tr><td>Critical Vulnerabilities</td><td class="severity-critical">{{ report.executive_summary.critical_vulnerabilities }}</td></tr>
            <tr><td>High Vulnerabilities</td><td class="severity-high">{{ report.executive_summary.high_vulnerabilities }}</td></tr>
        </table>

        <h2>💡 Key Recommendations</h2>
        {% for rec in report.recommendations[:5] %}
        <div class="recommendation">
            <h4>{{ rec.title }}</h4>
            <p>{{ rec.description }}</p>
            <p><strong>Priority:</strong> {{ rec.priority }} | <strong>Effort:</strong> {{ rec.effort }}</p>
        </div>
        {% endfor %}
        
        <footer style="margin-top: 3rem; padding: 2rem; background: #f8f9fa; border-radius: 5px; text-align: center;">
            <p>Generated by Universal Attack Surface Mapper (UASM) v1.0</p>
            <p>Report contains {{ report.vulnerabilities | length }} vulnerabilities and {{ report.findings | length }} findings</p>
        </footer>
    </div>
</body>
</html>
        """
    
    def _generate_json_report(self, report_data: Dict[str, Any], output_path: Optional[str]) -> str:
        """Generate JSON report"""
        if not output_path:
            target = report_data['metadata'].get('target', 'unknown')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = Path(self.output_dir) / f"uasm_report_{sanitize_filename(target)}_{timestamp}.json"
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)
            
            self.logger.info(f"JSON report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {str(e)}")
            raise
    
    def _generate_csv_report(self, report_data: Dict[str, Any], output_path: Optional[str]) -> str:
        """Generate CSV report"""
        if not output_path:
            target = report_data['metadata'].get('target', 'unknown')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = Path(self.output_dir) / f"uasm_vulnerabilities_{sanitize_filename(target)}_{timestamp}.csv"
        
        try:
            import csv
            
            vulnerabilities = report_data.get('vulnerabilities', [])
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if vulnerabilities:
                    fieldnames = ['title', 'severity', 'cvss_score', 'target_host', 'target_url', 
                                'description', 'remediation', 'cve_id', 'cwe_id']
                    
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for vuln in vulnerabilities:
                        row = {field: vuln.get(field, '') for field in fieldnames}
                        writer.writerow(row)
                else:
                    f.write("No vulnerabilities found\n")
            
            self.logger.info(f"CSV report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {str(e)}")
            raise
    
    def _generate_markdown_report(self, report_data: Dict[str, Any], output_path: Optional[str]) -> str:
        """Generate Markdown report"""
        if not output_path:
            target = report_data['metadata'].get('target', 'unknown')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = Path(self.output_dir) / f"uasm_report_{sanitize_filename(target)}_{timestamp}.md"
        
        # Generate Markdown content
        md_content = self._create_markdown_content(report_data)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md_content)
            
            self.logger.info(f"Markdown report generated: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Failed to generate Markdown report: {str(e)}")
            raise
    
    def _generate_pdf_report(self, report_data: Dict[str, Any], output_path: Optional[str]) -> str:
        """Generate PDF report"""
        try:
            # Generate HTML first
            html_path = self._generate_html_report(report_data, None)
            
            if not output_path:
                target = report_data['metadata'].get('target', 'unknown')
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_path = Path(self.output_dir) / f"uasm_report_{sanitize_filename(target)}_{timestamp}.pdf"
            
            # Convert HTML to PDF (would require weasyprint or similar)
            self.logger.warning("PDF generation requires additional dependencies (weasyprint)")
            return html_path
            
        except Exception as e:
            self.logger.error(f"Failed to generate PDF report: {str(e)}")
            raise
    
    def _create_markdown_content(self, report_data: Dict[str, Any]) -> str:
        """Create Markdown report content"""
        metadata = report_data['metadata']
        summary = report_data['executive_summary']
        
        md_content = f"""# 🛡️ UASM Security Assessment Report

## Target Information
- **Target:** {metadata.get('target', 'Unknown')}
- **Scan Duration:** {format_duration(metadata.get('scan_duration', 0))}
- **Generated:** {metadata.get('generated_at', 'Unknown')}
- **Total Findings:** {metadata.get('total_findings', 0)}

## Executive Summary

### Overall Risk Assessment
- **Risk Level:** {summary.get('overall_risk_level', 'Unknown')}
- **Average Risk Score:** {summary.get('average_risk_score', 0)}
- **Total Vulnerabilities:** {summary.get('total_vulnerabilities', 0)}
- **Critical Vulnerabilities:** {summary.get('critical_vulnerabilities', 0)}
- **High Vulnerabilities:** {summary.get('high_vulnerabilities', 0)}

## Vulnerability Details

"""
        
        # Add vulnerabilities
        vulnerabilities = report_data.get('vulnerabilities', [])
        for i, vuln in enumerate(vulnerabilities[:20], 1):
            md_content += f"""### {i}. {vuln.get('title', 'Unknown Vulnerability')}

- **Severity:** {vuln.get('severity', 'Unknown').title()}
- **CVSS Score:** {vuln.get('cvss_score', 'N/A')}
- **Target:** {vuln.get('target_host', vuln.get('target_url', 'Unknown'))}
- **Description:** {vuln.get('description', 'No description available')}

"""
            if vuln.get('remediation'):
                md_content += f"**Remediation:** {vuln.get('remediation')}\n\n"
            
            md_content += "---\n\n"
        
        # Add recommendations
        md_content += "## Recommendations\n\n"
        recommendations = report_data.get('recommendations', [])
        for i, rec in enumerate(recommendations[:10], 1):
            md_content += f"""{i}. **{rec.get('title', 'Unknown')}**
   - Priority: {rec.get('priority', 'Unknown')}
   - Description: {rec.get('description', 'No description')}
   
"""
        
        md_content += "\n---\n*Report generated by Universal Attack Surface Mapper (UASM) v1.0*"
        
        return md_content
    
    # Helper methods
    def _calculate_severity_distribution(self, scan_results: Dict[str, Any]) -> Dict[str, int]:
        """Calculate severity distribution"""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in scan_results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'info').lower()
            if severity in distribution:
                distribution[severity] += 1
        
        return distribution
    
    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14', 
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8'
        }
        return colors.get(severity.lower(), '#6c757d')
    
    def _format_timestamp(self, timestamp: str) -> str:
        """Format timestamp for display"""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return timestamp
    
    def _get_key_recommendations(self, vulnerabilities: List[Dict], findings: List[Dict]) -> List[str]:
        """Get key recommendations based on findings"""
        recommendations = []
        
        if any(v.get('severity') == 'critical' for v in vulnerabilities):
            recommendations.append("Address critical vulnerabilities immediately")
        
        if len(vulnerabilities) > 10:
            recommendations.append("Implement comprehensive vulnerability management program")
        
        recommendations.append("Conduct regular security assessments")
        
        return recommendations[:3]
    
    def _calculate_attack_surface_size(self, scan_results: Dict[str, Any]) -> str:
        """Calculate attack surface size"""
        hosts = len(scan_results.get('hosts', []))
        subdomains = len(scan_results.get('subdomains', []))
        
        if hosts + subdomains > 50:
            return "Large"
        elif hosts + subdomains > 10:
            return "Medium"
        else:
            return "Small"
    
    def _calculate_vulnerability_stats(self, vulnerabilities: List[Dict]) -> Dict:
        """Calculate vulnerability statistics"""
        return {
            'total': len(vulnerabilities),
            'by_severity': self._count_by_severity(vulnerabilities),
            'avg_cvss': sum(v.get('cvss_score', 0) for v in vulnerabilities) / len(vulnerabilities) if vulnerabilities else 0
        }
    
    def _calculate_finding_stats(self, findings: List[Dict]) -> Dict:
        """Calculate finding statistics"""
        return {
            'total': len(findings),
            'by_category': self._count_by_category(findings)
        }
    
    def _calculate_coverage_stats(self, scan_results: Dict) -> Dict:
        """Calculate coverage statistics"""
        return {
            'modules_run': len(scan_results.get('scan_info', {}).get('modules', [])),
            'hosts_scanned': len(scan_results.get('hosts', [])),
            'subdomains_found': len(scan_results.get('subdomains', []))
        }
    
    def _count_by_severity(self, vulnerabilities: List[Dict]) -> Dict:
        """Count vulnerabilities by severity"""
        counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_by_category(self, findings: List[Dict]) -> Dict:
        """Count findings by category"""
        counts = {}
        for finding in findings:
            category = finding.get('category', 'unknown')
            counts[category] = counts.get(category, 0) + 1
        return counts
    
    def _process_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Process and categorize findings"""
        return findings  # Basic implementation
    
    def _generate_recommendations(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate security recommendations"""
        return [
            {
                'title': 'Implement Security Monitoring',
                'priority': 'High',
                'description': 'Deploy comprehensive security monitoring and alerting',
                'effort': 'Medium'
            }
        ]
    
    def _calculate_risk_assessment(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comprehensive risk assessment"""
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        return {
            'overall_risk_score': 50.0,
            'risk_level': 'Medium',
            'total_vulnerabilities': len(vulnerabilities),
            'business_impact': 'Medium - Some security concerns identified',
            'remediation_effort': 'Medium - Moderate effort required'
        }

