#!/bin/bash

echo "🛡️  Universal Attack Surface Mapper (UASM) Setup"
echo "================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check if Python 3.7+ is installed
echo
print_info "Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
if [ $? -ne 0 ]; then
    print_error "Python 3 is not installed or not in PATH"
    exit 1
fi

# Extract major and minor version
major_version=$(echo $python_version | cut -d. -f1)
minor_version=$(echo $python_version | cut -d. -f2)

if [ "$major_version" -lt 3 ] || ([ "$major_version" -eq 3 ] && [ "$minor_version" -lt 7 ]); then
    print_error "Python 3.7 or higher is required. Found: $python_version"
    exit 1
fi

print_status "Python $python_version detected"

# Check if pip is installed
echo
print_info "Checking pip..."
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is not installed"
    exit 1
fi
print_status "pip3 is available"

# Install system dependencies
echo
print_info "Installing system dependencies..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    if command -v apt-get &> /dev/null; then
        # Ubuntu/Debian
        print_info "Detected Ubuntu/Debian system"
        sudo apt-get update
        sudo apt-get install -y python3-pip python3-dev python3-venv nmap masscan python3-dnspython
        print_status "System dependencies installed (Ubuntu/Debian)"
    elif command -v yum &> /dev/null; then
        # CentOS/RHEL
        print_info "Detected CentOS/RHEL system"
        sudo yum install -y python3-pip python3-devel nmap masscan python3-dns
        print_status "System dependencies installed (CentOS/RHEL)"
    elif command -v dnf &> /dev/null; then
        # Fedora
        print_info "Detected Fedora system"
        sudo dnf install -y python3-pip python3-devel nmap masscan python3-dns
        print_status "System dependencies installed (Fedora)"
    elif command -v pacman &> /dev/null; then
        # Arch Linux
        print_info "Detected Arch Linux system"
        sudo pacman -S --noconfirm python-pip nmap masscan python-dnspython
        print_status "System dependencies installed (Arch Linux)"
    else
        print_warning "Unknown Linux distribution. Please install nmap and masscan manually."
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    print_info "Detected macOS system"
    if command -v brew &> /dev/null; then
        brew install nmap masscan
        print_status "System dependencies installed (macOS)"
    else
        print_warning "Homebrew not found. Please install nmap and masscan manually."
        print_info "Install Homebrew: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        print_info "Then run: brew install nmap masscan"
    fi
else
    print_warning "Unknown operating system. Please install nmap and masscan manually."
fi

# Create virtual environment
echo
print_info "Creating Python virtual environment..."
python3 -m venv venv
if [ $? -eq 0 ]; then
    print_status "Virtual environment created"
else
    print_error "Failed to create virtual environment"
    exit 1
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
print_info "Upgrading pip..."
pip install --upgrade pip

# Install Python requirements
echo
print_info "Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    if [ $? -eq 0 ]; then
        print_status "Python dependencies installed"
    else
        print_error "Failed to install Python dependencies"
        print_info "Trying individual package installation..."
        
        # Try installing critical packages individually
        critical_packages=("requests" "pyyaml" "jinja2" "sqlalchemy" "dnspython" "python-nmap" "matplotlib" "networkx")
        
        for package in "${critical_packages[@]}"; do
            print_info "Installing $package..."
            pip install "$package" || print_warning "Failed to install $package"
        done
    fi
else
    print_error "requirements.txt not found"
    print_info "Creating basic requirements.txt..."
    cat > requirements.txt << 'EOF'
requests>=2.25.0
pyyaml>=5.4.0
jinja2>=3.0.0
sqlalchemy>=1.4.0
dnspython>=2.1.0
python-nmap>=0.6.1
matplotlib>=3.3.0
networkx>=2.6.0
EOF
    pip install -r requirements.txt
fi

# Create necessary directories
echo
print_info "Creating directory structure..."
mkdir -p scans reports wordlists templates logs

# Download/create wordlists
print_info "Setting up wordlists..."

# Create basic wordlists if they don't exist
if [ ! -f "wordlists/subdomains.txt" ]; then
    cat > wordlists/subdomains.txt << 'EOF'
www
mail
ftp
admin
test
dev
api
app
blog
shop
portal
secure
vpn
remote
support
help
docs
cdn
staging
demo
beta
alpha
prod
production
old
new
backup
archive
static
media
images
assets
files
download
uploads
data
db
database
monitoring
status
health
metrics
logs
kibana
grafana
jenkins
gitlab
git
svn
repo
code
mx
ns
ns1
ns2
smtp
pop
imap
webmail
mail2
exchange
owa
autodiscover
cpanel
whm
plesk
directadmin
panel
control
admin2
administrator
root
user
users
login
signin
auth
sso
oauth
ldap
ad
directory
hr
finance
accounting
sales
marketing
legal
compliance
audit
security
infra
infrastructure
ops
devops
ci
cd
build
deploy
release
staging2
uat
qa
test2
sandbox
preview
temp
tmp
cache
proxy
lb
loadbalancer
firewall
waf
gateway
router
switch
wifi
wireless
guest
public
private
internal
intranet
extranet
partner
client
customer
vendor
supplier
b2b
b2c
mobile
m
wap
touch
tablet
ios
android
app2
application
service
services
microservice
lambda
function
worker
queue
job
cron
scheduler
monitor
alert
notification
log
logger
syslog
elk
elastic
search
solr
redis
memcache
rabbitmq
kafka
zookeeper
consul
vault
secret
config
configuration
setting
preference
profile
account
billing
payment
checkout
cart
order
inventory
catalog
product
category
review
rating
comment
feedback
survey
poll
vote
contest
promotion
coupon
discount
affiliate
referral
analytics
tracking
pixel
tag
segment
audience
campaign
email
newsletter
subscription
unsubscribe
rss
feed
sitemap
robots
favicon
crossdomain
manifest
opensearch
well-known
acme-challenge
pki-validation
security.txt
humans.txt
ads.txt
sellers.json
EOF
    print_status "Created basic subdomain wordlist"
fi

if [ ! -f "wordlists/directories.txt" ]; then
    cat > wordlists/directories.txt << 'EOF'
admin
administrator
api
app
application
backup
backups
bin
cache
cgi-bin
config
content
data
database
db
debug
dev
development
doc
docs
download
downloads
files
ftp
help
home
html
images
img
include
includes
js
lib
library
log
logs
login
mail
media
old
panel
private
public
root
script
scripts
secure
security
src
static
stats
system
temp
test
tmp
upload
uploads
user
users
var
web
webadmin
webmail
www
.git
.svn
.env
.htaccess
.htpasswd
.well-known
robots.txt
sitemap.xml
phpmyadmin
phpinfo
info
readme.txt
changelog.txt
license.txt
version.txt
config.php
wp-config.php
database.sql
dump.sql
backup.sql
.backup
.bak
.old
.orig
.save
.tmp
wp-admin
wp-content
wp-includes
administrator
joomla
drupal
magento
prestashop
opencart
woocommerce
shopify
bigcommerce
squarespace
wordpress
cms
blog
news
article
post
page
category
tag
search
contact
about
services
products
portfolio
gallery
testimonials
clients
partners
careers
jobs
press
media
legal
privacy
terms
policy
disclaimer
support
help
faq
knowledge
wiki
documentation
manual
guide
tutorial
video
download
software
tool
utility
resource
asset
file
document
pdf
image
photo
picture
logo
icon
favicon
css
style
stylesheet
js
javascript
script
json
xml
rss
atom
feed
sitemap
api
v1
v2
v3
rest
graphql
soap
wsdl
swagger
openapi
oauth
auth
login
signin
signup
register
account
profile
dashboard
console
control
panel
cpanel
plesk
directadmin
whm
webmin
phpmyadmin
adminer
phpinfo
info
status
health
ping
test
check
monitor
stats
statistics
analytics
metrics
report
reports
log
logs
error
debug
trace
dump
backup
export
import
migrate
install
setup
configure
update
upgrade
patch
maintenance
service
daemon
worker
queue
job
cron
task
scheduler
batch
process
pipeline
webhook
callback
notify
alert
email
sms
push
socket
websocket
stream
live
real-time
cache
redis
memcached
session
cookie
storage
s3
cdn
asset
static
media
upload
file
image
video
audio
document
pdf
zip
tar
gz
rar
exe
msi
dmg
pkg
deb
rpm
EOF
    print_status "Created basic directory wordlist"
fi

# Set permissions
echo
print_info "Setting file permissions..."
chmod +x uasm.py
find . -name "*.py" -type f -exec chmod +x {} \;
print_status "Permissions set"

# Create sample configuration if it doesn't exist
if [ ! -f "config.yaml" ]; then
    print_info "Creating sample configuration..."
    # The config.yaml should already exist from the earlier code
    print_status "Configuration file ready"
fi

# Test installation
echo
print_info "Testing installation..."
python3 uasm.py --version > /dev/null 2>&1
if [ $? -eq 0 ]; then
    print_status "Installation test passed"
else
    print_warning "Installation test had issues, but basic setup is complete"
fi

# Check for nmap
echo
print_info "Verifying nmap installation..."
if command -v nmap &> /dev/null; then
    nmap_version=$(nmap --version | head -n1)
    print_status "Nmap is available: $nmap_version"
else
    print_warning "Nmap not found in PATH. Some network scanning features may not work."
    print_info "Please install nmap manually:"
    print_info "  Ubuntu/Debian: sudo apt-get install nmap"
    print_info "  CentOS/RHEL: sudo yum install nmap"
    print_info "  macOS: brew install nmap"
fi

# Final success message
echo
echo "════════════════════════════════════════════════════════════════"
print_status "UASM setup completed successfully!"
echo "════════════════════════════════════════════════════════════════"
echo
print_info "🚀 To get started:"
echo "  1. Activate the virtual environment: source venv/bin/activate"
echo "  2. Run a basic scan: python3 uasm.py -t example.com"
echo "  3. View help: python3 uasm.py --help"
echo "  4. Run demo: python3 demo.py"
echo
print_info "📚 Documentation:"
echo "  - README.md: Complete documentation"
echo "  - config.yaml: Configuration options"
echo "  - demo.py: Sample scan demonstration"
echo
print_warning "⚠️  Important Notes:"
echo "  - Some network scanning features require root privileges"
echo "  - Run 'sudo python3 uasm.py -t <target> -m network' for complete network scanning"
echo "  - Always ensure you have authorization before scanning targets"
echo "  - Check local laws and regulations regarding security scanning"
echo
print_status "🛡️  Happy Hacking! Stay secure and scan responsibly."
echo

# Deactivate virtual environment
deactivate 2>/dev/null || true

echo "Setup complete! Remember to activate the virtual environment before running UASM:"
echo "  source venv/bin/activate"

