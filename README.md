
# 🛡️ Universal Attack Surface Mapper (UASM)

A comprehensive cybersecurity tool for automated attack surface mapping and vulnerability assessment.

## 🎯 Overview

UASM is a modular security scanner designed for penetration testers, bug bounty hunters, and security professionals. It automatically maps attack surfaces across networks, web applications, APIs, and cloud services.

## ✨ Features

### Core Capabilities
- **Network Reconnaissance** - Port scanning, service detection, OS fingerprinting
- **Web Application Security** - Subdomain enumeration, directory bruteforcing, technology detection
- **API Security Testing** - REST/GraphQL endpoint discovery and security assessment
- **Cloud Asset Discovery** - AWS S3, GCP, Azure resource enumeration
- **Results Correlation** - Cross-module finding correlation and attack path generation
- **Multi-format Reporting** - HTML, JSON, CSV, Markdown, PDF reports

### Technical Features
- **Modular Architecture** - Plugin-based scanner modules
- **Multi-threaded Performance** - High-speed concurrent scanning
- **Database Integration** - SQLite/PostgreSQL result storage
- **Data Visualization** - Network graphs and vulnerability matrices
- **Configuration Management** - YAML-based configuration system
- **Comprehensive Logging** - Multi-level logging with rotation

## 🚀 Quick Start

### Installation
```
# Clone or download UASM
cd universal_attack_surface_mapper

# Run automated setup
chmod +x setup.sh
./setup.sh

# Activate virtual environment
source venv/bin/activate
```

### Basic Usage
```
# Simple domain scan
python3 uasm.py -t example.com

# Network range scan
python3 uasm.py -t 192.168.1.0/24 -m network

# Web reconnaissance with reports
python3 uasm.py -t example.com -m web -r html,json

# Comprehensive scan
python3 uasm.py -t example.com -m network,web,api,cloud --visualize
```

## 📋 Command Line Options

```
Usage: uasm.py -t  [options]

Target Specification:
  -t, --target TARGET     Target (domain, IP, CIDR, URL)

Scanner Modules:
  -m, --modules LIST      Modules to run: network,web,api,cloud

Performance:
  -T, --threads N         Number of concurrent threads (default: 50)
  --timeout SECONDS       Scan timeout in seconds (default: 3600)

Output:
  -r, --report FORMAT     Report format: html,json,csv,markdown,pdf
  -o, --output-dir DIR    Output directory
  --visualize            Generate visualizations

Configuration:
  -c, --config FILE       Configuration file path
  -v, --verbose          Verbose output
```

## 🔧 Configuration

UASM uses YAML configuration files. Edit `config.yaml` to customize:

```
general:
  max_threads: 50
  scan_timeout: 3600

network_scanner:
  timeout: 30
  top_ports: 1000

web_recon:
  threads: 20
  subdomain_wordlist: "wordlists/subdomains.txt"

# ... more options
```

## 📊 Output Formats

### HTML Reports
Interactive dashboard with:
- Executive summary and risk assessment
- Detailed vulnerability listings
- Network topology visualizations
- Remediation recommendations

### JSON Reports
Machine-readable structured data for:
- API integration
- Custom analysis tools
- Data pipeline integration

### CSV Reports
Spreadsheet-compatible exports for:
- Vulnerability tracking
- Risk management
- Compliance reporting

## 🏗️ Architecture

```
UASM Core Engine
├── Scanner Modules
│   ├── Network Scanner (Nmap integration)
│   ├── Web Reconnaissance (DNS, HTTP analysis)
│   ├── API Security (OpenAPI/GraphQL testing)
│   └── Cloud Reconnaissance (AWS/GCP/Azure)
├── Results Correlator (Cross-module analysis)
├── Report Generator (Multi-format output)
└── Data Visualizer (Graphs and charts)
```

## 🔍 Scanner Modules

### Network Scanner
- **Port Scanning**: TCP/UDP port discovery with Nmap
- **Service Detection**: Banner grabbing and version identification
- **OS Fingerprinting**: Operating system detection
- **Vulnerability Assessment**: CVE correlation and risk scoring

### Web Reconnaissance
- **Subdomain Enumeration**: DNS bruteforcing and certificate transparency
- **Directory Bruteforcing**: Common path and file discovery
- **Technology Detection**: Web server and framework identification
- **SSL/TLS Analysis**: Certificate validation and configuration review

### API Security
- **Endpoint Discovery**: REST and GraphQL endpoint enumeration
- **Documentation Analysis**: Swagger/OpenAPI specification parsing
- **Authentication Testing**: Bypass and misconfiguration detection
- **Input Validation**: Injection vulnerability assessment

### Cloud Reconnaissance
- **AWS Services**: S3 bucket enumeration and permission testing
- **Google Cloud**: Storage bucket and service discovery
- **Azure Resources**: Blob container and application assessment
- **Multi-cloud Correlation**: Cross-platform asset mapping

## 📈 Sample Results

```
# Run demo to see sample output
python3 demo.py

# Example scan statistics
📊 Scan Summary:
🖥️  Hosts discovered: 5
🌐 Subdomains found: 23
🚨 Vulnerabilities: 12
📋 Total findings: 45
```

## 🔒 Security & Legal

### Important Notes
- **Authorization Required**: Only scan systems you own or have explicit permission to test
- **Legal Compliance**: Ensure compliance with local laws and regulations
- **Responsible Disclosure**: Follow responsible disclosure practices for vulnerabilities
- **Rate Limiting**: Use appropriate delays to avoid overwhelming target systems

### Best Practices
- Run from isolated environments when possible
- Use VPN or proxy for external scans
- Monitor target system performance during scans
- Secure scan results and logs appropriately

## 🛠️ Advanced Usage

### Custom Configurations
```
# Use custom config file
python3 uasm.py -t example.com -c custom_config.yaml

# High-performance scanning
python3 uasm.py -t example.com -T 200 --timeout 7200

# Network scanning with elevated privileges
sudo python3 uasm.py -t 192.168.1.0/24 -m network
```

### Integration Examples
```
# Python API usage
from uasm.core.scanner import UASMScanner
from uasm.core.config import Config

config = Config()
scanner = UASMScanner(config)
scanner.set_target("example.com")
results = scanner.run()
```

## 🔧 Troubleshooting

### Common Issues

**Permission Denied for Network Scanning**
```
# Solution: Run with sudo for raw socket access
sudo python3 uasm.py -t example.com -m network
```

**Missing Dependencies**
```
# Solution: Reinstall requirements
pip install -r requirements.txt
```

**Nmap Not Found**
```
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# CentOS/RHEL
sudo yum install nmap
```

## 🚀 Development

### Adding Custom Modules
1. Create new module in `uasm/modules/`
2. Inherit from base scanner class
3. Implement required methods
4. Register in scanner engine

### Custom Wordlists
1. Place wordlists in `wordlists/` directory
2. Update `config.yaml` with file paths
3. Ensure proper format (one entry per line)

## 📚 Documentation

- **Configuration Reference**: See `config.yaml` for all options
- **API Documentation**: Python docstrings in source code
- **Examples**: Check `demo.py` for usage examples
- **Troubleshooting**: See common issues section above

## 🤝 Contributing

UASM is designed for security professionals and researchers. Contributions welcome for:
- New scanner modules
- Enhanced reporting formats
- Performance improvements
- Documentation updates

## ⚠️ Disclaimer

This tool is for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any systems. The developers are not responsible for any misuse or damage caused by this tool.

## 📞 Support

For issues and questions:
- Check troubleshooting section
- Review configuration options
- Examine log files for errors
- Verify target permissions and connectivity

---

**🛡️ Happy Hacking! Stay secure and scan responsibly.**
```

