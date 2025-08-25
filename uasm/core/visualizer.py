"""
Data Visualizer Module for UASM
Creates visual representations of scan results and security data
"""

import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import json
import base64
import io

from uasm.core.logger import create_module_logger


class UASMVisualizer:
    """Create visual representations of UASM scan results"""
    
    def __init__(self, config):
        """Initialize the visualizer"""
        self.config = config
        self.logger = create_module_logger('UASMVisualizer')
        
        # Set matplotlib to non-interactive backend
        plt.switch_backend('Agg')
        
        # Visualization configuration
        self.colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8',
            'host': '#6f42c1',
            'subdomain': '#20c997',
            'service': '#e83e8c',
            'vulnerability': '#dc3545'
        }
        
        self.logger.info("UASM Visualizer initialized")
    
    def create_network_graph(self, scan_results: Dict[str, Any], 
                           output_path: Optional[str] = None) -> str:
        """Create network topology graph"""
        self.logger.info("Creating network topology graph...")
        
        # Create directed graph
        G = nx.DiGraph()
        
        # Add hosts as nodes
        hosts = scan_results.get('hosts', [])
        subdomains = scan_results.get('subdomains', [])
        
        # Add host nodes
        for host in hosts:
            ip = host.get('ip_address', '')
            hostname = host.get('hostname', ip)
            
            G.add_node(ip, 
                      label=hostname or ip,
                      node_type='host',
                      status=host.get('status', 'unknown'))
            
            # Add services as connected nodes
            for port in host.get('ports', []):
                if port.get('state') == 'open':
                    service_id = f"{ip}:{port.get('port')}"
                    service_label = f"{port.get('service', 'unknown')}\n{port.get('port')}"
                    
                    G.add_node(service_id,
                              label=service_label,
                              node_type='service',
                              service=port.get('service', 'unknown'))
                    
                    G.add_edge(ip, service_id)
        
        # Add subdomain nodes and connections
        for subdomain_info in subdomains:
            subdomain = subdomain_info.get('subdomain', '')
            ip = subdomain_info.get('ip_address', '')
            
            if subdomain:
                G.add_node(subdomain,
                          label=subdomain,
                          node_type='subdomain',
                          status_code=subdomain_info.get('status_code', 0))
                
                # Connect to host if IP is known
                if ip and ip in G:
                    G.add_edge(subdomain, ip)
        
        # Create visualization
        return self._render_network_graph(G, output_path)
    
    def _render_network_graph(self, G: nx.DiGraph, output_path: Optional[str] = None) -> str:
        """Render the network graph"""
        fig, ax = plt.subplots(1, 1, figsize=(16, 12))
        
        # Calculate layout
        pos = nx.spring_layout(G, k=3, iterations=50)
        
        # Separate nodes by type
        node_colors = []
        node_sizes = []
        
        for node in G.nodes():
            node_data = G.nodes[node]
            node_type = node_data.get('node_type', 'unknown')
            
            if node_type == 'host':
                node_colors.append(self.colors['host'])
                node_sizes.append(1000)
            elif node_type == 'service':
                node_colors.append(self.colors['service'])
                node_sizes.append(600)
            elif node_type == 'subdomain':
                node_colors.append(self.colors['subdomain'])
                node_sizes.append(800)
            else:
                node_colors.append('#cccccc')
                node_sizes.append(300)
        
        # Draw graph
        nx.draw_networkx_nodes(G, pos, 
                              node_color=node_colors,
                              node_size=node_sizes,
                              alpha=0.7,
                              ax=ax)
        
        nx.draw_networkx_edges(G, pos,
                              edge_color='#666666',
                              alpha=0.5,
                              arrows=True,
                              arrowsize=20,
                              ax=ax)
        
        # Add labels
        labels = {node: G.nodes[node].get('label', node)[:15] 
                 for node in G.nodes()}
        
        nx.draw_networkx_labels(G, pos, labels, 
                               font_size=8,
                               font_weight='bold',
                               ax=ax)
        
        # Create legend
        legend_elements = [
            mpatches.Patch(color=self.colors['host'], label='Hosts'),
            mpatches.Patch(color=self.colors['service'], label='Services'),
            mpatches.Patch(color=self.colors['subdomain'], label='Subdomains'),
        ]
        
        ax.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(0, 1))
        ax.set_title('Network Topology and Security Overview', fontsize=16, fontweight='bold')
        ax.axis('off')
        
        plt.tight_layout()
        
        # Save or return as base64
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Network graph saved to: {output_path}")
            plt.close()
            return str(output_path)
        else:
            # Return as base64
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
            buffer.seek(0)
            graph_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            buffer.close()
            plt.close()
            return graph_base64
    
    def create_vulnerability_matrix(self, scan_results: Dict[str, Any],
                                  output_path: Optional[str] = None) -> str:
        """Create vulnerability risk matrix"""
        self.logger.info("Creating vulnerability risk matrix...")
        
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        if not vulnerabilities:
            self.logger.warning("No vulnerabilities to visualize")
            return ""
        
        # Prepare data for matrix
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        severity_counts = {sev: 0 for sev in severity_order}
        
        # Count vulnerabilities by severity
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Create matrix visualization
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))
        
        # Pie chart for severity distribution
        sizes = [count for count in severity_counts.values() if count > 0]
        labels = [sev.title() for sev, count in severity_counts.items() if count > 0]
        colors = [self.colors[sev] for sev in severity_counts.keys() if severity_counts[sev] > 0]
        
        if sizes:
            wedges, texts, autotexts = ax1.pie(sizes, labels=labels, colors=colors,
                                             autopct='%1.1f%%', startangle=90)
            
            ax1.set_title('Vulnerability Severity Distribution', fontsize=14, fontweight='bold')
        
        # Bar chart for detailed counts
        ax2.bar(range(len(severity_order)), 
               [severity_counts[sev] for sev in severity_order],
               color=[self.colors[sev] for sev in severity_order])
        
        ax2.set_xlabel('Severity Level')
        ax2.set_ylabel('Count')
        ax2.set_title('Vulnerability Count by Severity', fontsize=14, fontweight='bold')
        ax2.set_xticks(range(len(severity_order)))
        ax2.set_xticklabels([sev.title() for sev in severity_order])
        
        # Add count labels on bars
        for i, count in enumerate([severity_counts[sev] for sev in severity_order]):
            if count > 0:
                ax2.text(i, count + 0.1, str(count), ha='center', fontweight='bold')
        
        plt.tight_layout()
        
        # Save or return as base64
        if output_path:
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Vulnerability matrix saved to: {output_path}")
            plt.close()
            return str(output_path)
        else:
            buffer = io.BytesIO()
            plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight')
            buffer.seek(0)
            matrix_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            buffer.close()
            plt.close()
            return matrix_base64
    
    def generate_dashboard_assets(self, scan_results: Dict[str, Any], 
                                output_dir: str) -> Dict[str, str]:
        """Generate all visualization assets for dashboard"""
        self.logger.info(f"Generating dashboard assets in: {output_dir}")
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        assets = {}
        
        try:
            # Network graph
            network_path = output_path / 'network_graph.png'
            self.create_network_graph(scan_results, str(network_path))
            assets['network_graph'] = str(network_path)
            
            # Vulnerability matrix
            vuln_path = output_path / 'vulnerability_matrix.png'
            self.create_vulnerability_matrix(scan_results, str(vuln_path))
            assets['vulnerability_matrix'] = str(vuln_path)
            
        except Exception as e:
            self.logger.error(f"Error generating dashboard assets: {str(e)}")
        
        self.logger.info(f"Generated {len(assets)} dashboard assets")
        return assets
    
    def export_graph_data(self, scan_results: Dict[str, Any], 
                         output_path: str) -> str:
        """Export graph data in JSON format for web visualization"""
        self.logger.info(f"Exporting graph data to: {output_path}")
        
        # Prepare graph data structure
        graph_data = {
            'nodes': [],
            'edges': [],
            'metadata': {
                'total_hosts': len(scan_results.get('hosts', [])),
                'total_subdomains': len(scan_results.get('subdomains', [])),
                'total_vulnerabilities': len(scan_results.get('vulnerabilities', [])),
                'scan_target': scan_results.get('scan_info', {}).get('target', 'unknown')
            }
        }
        
        node_id = 0
        
        # Add host nodes
        for host in scan_results.get('hosts', []):
            ip = host.get('ip_address', '')
            hostname = host.get('hostname', ip)
            
            graph_data['nodes'].append({
                'id': node_id,
                'label': hostname or ip,
                'type': 'host',
                'ip_address': ip,
                'hostname': hostname,
                'status': host.get('status', 'unknown'),
                'open_ports': len([p for p in host.get('ports', []) if p.get('state') == 'open'])
            })
            
            node_id += 1
        
        # Save graph data
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(graph_data, f, indent=2, default=str)
            
            self.logger.info(f"Graph data exported successfully: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Failed to export graph data: {str(e)}")
            raise

