#!/bin/bash

# Wireshark Setup Script for Parrot OS
# This script installs and configures Wireshark with security monitoring filters

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

error() {
    echo -e "${RED}✗ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    error "This script should not be run as root. Use sudo for installation if needed."
    exit 1
fi

# Function to install Wireshark
install_wireshark() {
    log "Installing Wireshark and related tools..."

    # Update package list
    sudo apt update

    # Install Wireshark and tools
    sudo apt install -y wireshark wireshark-common tshark tcpdump ngrep

    # Add user to wireshark group for non-root capture
    sudo usermod -a -G wireshark $USER

    success "Wireshark installed successfully"
}

# Function to create capture filters
create_capture_filters() {
    log "Creating capture filter configurations..."

    # Create filters directory
    mkdir -p ~/wireshark_filters
    mkdir -p ~/wireshark_captures

    # Basic security monitoring filters
    cat > ~/wireshark_filters/security_filters.txt << 'EOF'
# SSH traffic monitoring
tcp port 22

# HTTP/HTTPS traffic
tcp port 80 or tcp port 443

# Suspicious ports (RDP, VNC)
tcp port 3389 or tcp port 5900 or tcp port 5901

# ICMP traffic (ping scans)
icmp

# DNS queries
udp port 53

# FTP traffic
tcp port 21 or tcp port 20

# SMB/CIFS traffic
tcp port 445 or tcp port 139

# Telnet (insecure)
tcp port 23

# SMTP traffic
tcp port 25 or tcp port 587 or tcp port 465
EOF

    # Advanced security filters
    cat > ~/wireshark_filters/advanced_filters.txt << 'EOF'
# SYN scan detection
tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0

# Port scanning patterns
tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst|tcp-push|tcp-ack|tcp-urg) != 0

# Large packets (potential data exfiltration)
frame.len > 1500

# Unusual protocols on common ports
not (tcp or udp or icmp) and (port 80 or port 443)

# ARP poisoning detection
arp.duplicate-address-detected or arp

# TCP RST packets (connection resets)
tcp[tcpflags] & (tcp-rst) != 0

# UDP floods
udp and frame.len > 1000

# Fragmented packets
ip.flags.df == 0 and ip.frag_offset > 0

# Malformed packets
tcp.len == 0 and tcp.flags.syn == 1

# Slowloris attack detection
tcp.flags.syn == 1 and tcp.window_size == 0
EOF

    # Protocol-specific filters
    cat > ~/wireshark_filters/protocol_filters.txt << 'EOF'
# HTTP methods
http.request.method == "GET" or http.request.method == "POST"

# HTTPS certificate errors
ssl.handshake.certificate

# DNS tunneling detection
dns.qry.name len > 50

# FTP commands
ftp.request.command

# SMB commands
smb.cmd

# RDP connections
rdp

# VNC connections
vnc
EOF

    success "Capture filters created"
}

# Function to create monitoring scripts
create_monitoring_scripts() {
    log "Creating monitoring and analysis scripts..."

    # Main monitoring script
    cat > ~/wireshark_monitor.sh << 'EOF'
#!/bin/bash

INTERFACE=${1:-"eth0"}
FILTER_FILE=${2:-"~/wireshark_filters/security_filters.txt"}
DURATION=${3:-3600}
OUTPUT_DIR="~/wireshark_captures"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $OUTPUT_DIR

echo "Starting Wireshark capture on $INTERFACE"
echo "Using filters from $FILTER_FILE"
echo "Duration: $DURATION seconds"
echo "Output: $OUTPUT_DIR/capture_$TIMESTAMP.pcap"

# Expand tilde in paths
FILTER_FILE_EXPANDED=$(eval echo $FILTER_FILE)
OUTPUT_DIR_EXPANDED=$(eval echo $OUTPUT_DIR)

# Build filter string
FILTER_STRING=$(grep -v '^#' "$FILTER_FILE_EXPANDED" | grep -v '^$' | tr '\n' ' or ' | sed 's/ or $//')

echo "Applied filter: $FILTER_STRING"

# Start capture with tshark
tshark -i $INTERFACE \
       -f "$FILTER_STRING" \
       -w "$OUTPUT_DIR_EXPANDED/capture_$TIMESTAMP.pcap" \
       -b duration:$DURATION \
       -b files:24 \
       -q

echo "Capture completed. Files saved in $OUTPUT_DIR_EXPANDED"
echo "To analyze: wireshark $OUTPUT_DIR_EXPANDED/capture_$TIMESTAMP.pcap"
EOF

    chmod +x ~/wireshark_monitor.sh

    # Quick analysis script
    cat > ~/wireshark_analyze.sh << 'EOF'
#!/bin/bash

PCAP_FILE=$1

if [ -z "$PCAP_FILE" ]; then
    echo "Usage: $0 <pcap_file>"
    echo "Analyzes a Wireshark capture file for security events"
    exit 1
fi

if [ ! -f "$PCAP_FILE" ]; then
    echo "Error: File $PCAP_FILE not found"
    exit 1
fi

echo "Analyzing capture file: $PCAP_FILE"
echo "=================================="

# Basic statistics
echo "=== Capture Statistics ==="
capinfos "$PCAP_FILE" | head -10

echo ""
echo "=== Protocol Distribution ==="
tshark -r "$PCAP_FILE" -q -z io,phs

echo ""
echo "=== Top Source IPs ==="
tshark -r "$PCAP_FILE" -T fields -e ip.src | sort | uniq -c | sort -nr | head -10

echo ""
echo "=== Top Destination IPs ==="
tshark -r "$PCAP_FILE" -T fields -e ip.dst | sort | uniq -c | sort -nr | head -10

echo ""
echo "=== Top Source Ports ==="
tshark -r "$PCAP_FILE" -T fields -e tcp.srcport -e udp.srcport | grep -v "^$" | sort | uniq -c | sort -nr | head -10

echo ""
echo "=== Top Destination Ports ==="
tshark -r "$PCAP_FILE" -T fields -e tcp.dstport -e udp.dstport | grep -v "^$" | sort | uniq -c | sort -nr | head -10

echo ""
echo "=== Suspicious Connections ==="
echo "Failed connections (RST packets):"
tshark -r "$PCAP_FILE" -Y "tcp.flags.reset == 1" -c 10

echo ""
echo "Large packets (>1500 bytes):"
tshark -r "$PCAP_FILE" -Y "frame.len > 1500" -c 10

echo ""
echo "ICMP traffic (potential scanning):"
tshark -r "$PCAP_FILE" -Y "icmp" -c 10

echo ""
echo "Analysis completed."
EOF

    chmod +x ~/wireshark_analyze.sh

    # Real-time monitoring script
    cat > ~/wireshark_realtime.sh << 'EOF'
#!/bin/bash

INTERFACE=${1:-"eth0"}
FILTER=${2:-"tcp port 22 or tcp port 80 or tcp port 443"}

echo "Starting real-time Wireshark monitoring on $INTERFACE"
echo "Filter: $FILTER"
echo "Press Ctrl+C to stop"
echo ""

tshark -i $INTERFACE \
       -f "$FILTER" \
       -T fields \
       -e frame.time \
       -e ip.src \
       -e ip.dst \
       -e tcp.srcport \
       -e tcp.dstport \
       -e _ws.col.Protocol \
       -e _ws.col.Info \
       -l
EOF

    chmod +x ~/wireshark_realtime.sh

    success "Monitoring scripts created"
}

# Function to configure Wireshark preferences
configure_wireshark() {
    log "Configuring Wireshark preferences..."

    # Create custom preferences
    mkdir -p ~/.config/wireshark

    cat > ~/.config/wireshark/preferences << 'EOF'
# Custom Wireshark preferences for security monitoring

# General settings
gui.geometry.main.x: 0
gui.geometry.main.y: 0
gui.geometry.main.width: 1200
gui.geometry.main.height: 800

# Protocol preferences
tcp.desegment_tcp_streams: TRUE
tcp.analyze_sequence_numbers: TRUE
tcp.relative_sequence_numbers: TRUE
http.decompress_gzip: TRUE
http.decompress_brotli: TRUE

# Security-related settings
tcp.check_checksum: TRUE
ip.check_checksum: TRUE
udp.check_checksum: TRUE

# Display settings
gui.column.format:"No.","%m","Time","%t","Source","%s","Destination","%d","Protocol","%p","Length","%L","Info","%i"
EOF

    # Create color filters for security events
    cat > ~/.config/wireshark/colorfilters << 'EOF'
# Security monitoring color filters

# Red: Suspicious TCP flags (potential scans)
@tcp.flags.syn==1 and tcp.flags.ack==0@

# Orange: RST packets (connection resets)
@tcp.flags.reset==1@

# Yellow: ICMP traffic (ping scans)
@icmp@

# Purple: Large packets (potential exfiltration)
@frame.len > 1500@

# Blue: HTTP traffic
@tcp.port == 80 or tcp.port == 8080@

# Green: HTTPS traffic
@tcp.port == 443 or tcp.port == 8443@

# Gray: DNS traffic
@udp.port == 53@
EOF

    success "Wireshark preferences configured"
}

# Function to create systemd service for automated capture
create_systemd_service() {
    log "Creating systemd service for automated capture..."

    sudo tee /etc/systemd/system/wireshark-monitor.service << 'EOF'
[Unit]
Description=Wireshark Security Monitoring
After=network.target

[Service]
Type=simple
User=wireshark
ExecStart=/home/%u/wireshark_monitor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo tee /etc/systemd/system/wireshark-monitor.timer << 'EOF'
[Unit]
Description=Run Wireshark monitoring every hour
Requires=wireshark-monitor.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # Note: Service needs user configuration
    warning "Systemd service created. Edit /etc/systemd/system/wireshark-monitor.service to set correct user"

    success "Systemd service templates created"
}

# Function to verify installation
verify_installation() {
    log "Verifying Wireshark installation..."

    # Check if Wireshark is installed
    if command -v wireshark >/dev/null 2>&1; then
        success "Wireshark is installed: $(wireshark --version | head -1)"
    else
        error "Wireshark is not installed"
        return 1
    fi

    # Check if tshark is available
    if command -v tshark >/dev/null 2>&1; then
        success "TShark is available: $(tshark --version | head -1)"
    else
        error "TShark is not available"
        return 1
    fi

    # Check user group membership
    if groups $USER | grep -q wireshark; then
        success "User $USER is in wireshark group"
    else
        warning "User $USER is not in wireshark group. Run: sudo usermod -a -G wireshark $USER"
    fi

    # Check filter files
    if [ -f ~/wireshark_filters/security_filters.txt ]; then
        success "Security filters created"
    else
        error "Security filters not found"
        return 1
    fi

    # Check scripts
    if [ -x ~/wireshark_monitor.sh ]; then
        success "Monitoring scripts created"
    else
        error "Monitoring scripts not found"
        return 1
    fi

    # Test capture capability (without root)
    if sudo -n tshark -D >/dev/null 2>&1; then
        interfaces=$(sudo tshark -D | wc -l)
        success "Capture interfaces available: $interfaces"
    else
        warning "Cannot test capture interfaces (may require logout/login for group membership)"
    fi

    success "Wireshark installation verification completed"
}

# Function to display usage information
show_usage() {
    echo "Wireshark Setup Script for Parrot OS"
    echo "===================================="
    echo ""
    echo "This script installs and configures Wireshark with security monitoring filters."
    echo ""
    echo "Usage:"
    echo "  $0 [options]"
    echo ""
    echo "Options:"
    echo "  --help          Show this help message"
    echo "  --no-service    Skip systemd service creation"
    echo ""
    echo "After installation:"
    echo "  1. Logout and login again for group membership to take effect"
    echo "  2. Run: ~/wireshark_monitor.sh [interface] [filter_file] [duration]"
    echo "  3. Run: ~/wireshark_analyze.sh <pcap_file>"
    echo "  4. Run: ~/wireshark_realtime.sh [interface] [filter]"
    echo ""
    echo "Filter files are located in ~/wireshark_filters/"
    echo "Captures are saved in ~/wireshark_captures/"
}

# Main function
main() {
    local skip_service=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help)
                show_usage
                exit 0
                ;;
            --no-service)
                skip_service=true
                shift
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    echo "Wireshark Setup Script for Parrot OS"
    echo "===================================="

    install_wireshark
    create_capture_filters
    create_monitoring_scripts
    configure_wireshark

    if [[ "$skip_service" != true ]]; then
        create_systemd_service
    fi

    verify_installation

    success "Wireshark setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Logout and login again for wireshark group membership"
    echo "2. Test capture: ~/wireshark_monitor.sh eth0"
    echo "3. View captures: wireshark ~/wireshark_captures/"
    echo "4. Check filters: cat ~/wireshark_filters/security_filters.txt"
}

# Run main function
main "$@"