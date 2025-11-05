#!/bin/bash

# macOS Logging Setup Script
# This script configures macOS systems to forward logs to Wazuh manager

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

# Check if running on macOS
check_macos() {
    if [[ "$OSTYPE" != "darwin"* ]]; then
        error "This script is designed for macOS systems only"
        exit 1
    fi

    success "Running on macOS: $(sw_vers -productVersion)"
}

# Function to install Wazuh agent on macOS
install_wazuh_agent_macos() {
    local manager_ip=$1

    if [[ -z "$manager_ip" ]]; then
        error "Manager IP is required for agent installation"
        exit 1
    fi

    log "Installing Wazuh Agent on macOS..."

    # Download Wazuh agent for macOS
    local agent_version="4.3.10"
    local agent_pkg="wazuh-agent-${agent_version}-1.pkg"

    if [ ! -f "$agent_pkg" ]; then
        log "Downloading Wazuh agent..."
        curl -O "https://packages.wazuh.com/4.x/macos/${agent_pkg}"
    fi

    # Install the package
    sudo installer -pkg "$agent_pkg" -target /

    # Configure agent
    sudo tee /Library/Ossec/etc/ossec.conf > /dev/null << EOF
<ossec_config>
  <client>
    <server>
      <address>$manager_ip</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>macos</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <!-- macOS log collection -->
  <localfile>
    <log_format>macos</log_format>
    <location>/private/var/log/system.log</location>
  </localfile>

  <localfile>
    <log_format>macos</log_format>
    <location>/private/var/log/install.log</location>
  </localfile>

  <localfile>
    <log_format>macos</log_format>
    <location>/private/var/log/appfirewall.log</location>
  </localfile>

  <localfile>
    <log_format>macos</log_format>
    <location>/private/var/log/opendirectoryd.log</location>
  </localfile>
</ossec_config>
EOF

    success "Wazuh Agent installed and configured"
}

# Function to configure macOS logging
configure_macos_logging() {
    log "Configuring macOS system logging..."

    # Create Wazuh log directory
    sudo mkdir -p /private/var/log/wazuh

    # Configure syslog to forward to Wazuh
    sudo tee /etc/syslog.conf > /dev/null << EOF
# Wazuh log forwarding
*.* @wazuh-manager-ip:514

# Local logging
*.err;kern.warning;auth.notice;mail.crit /dev/console
*.notice;authpriv.none;kern.debug;lpr.info;mail.crit;news.err /var/log/system.log
EOF

    # Alternative: Configure with syslog-ng if available
    if command -v syslog-ng >/dev/null 2>&1; then
        sudo tee /etc/syslog-ng/conf.d/wazuh.conf > /dev/null << EOF
destination d_wazuh {
    syslog("wazuh-manager-ip" port(514) transport("tcp"));
};

log {
    source(s_src);
    destination(d_wazuh);
};
EOF
        sudo syslog-ng-ctl reload
    fi

    # Configure unified logging for macOS 10.12+
    if sw_vers -productVersion | grep -q "10\.[1-9][2-9]\|1[0-9]\."; then
        log "Configuring unified logging..."

        # Create plist for log forwarding
        sudo tee /Library/LaunchDaemons/com.wazuh.logging.plist > /dev/null << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wazuh.logging</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/log</string>
        <string>stream</string>
        <string>--predicate</string>
        <string>eventMessage CONTAINS "error" OR eventMessage CONTAINS "fail" OR eventMessage CONTAINS "denied"</string>
        <string>--style</string>
        <string>syslog</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/private/var/log/wazuh/unified.log</string>
    <key>StandardErrorPath</key>
    <string>/private/var/log/wazuh/unified_error.log</string>
</dict>
</plist>
EOF

        # Load the launch daemon
        sudo launchctl load /Library/LaunchDaemons/com.wazuh.logging.plist
    fi

    # Configure log rotation
    sudo tee /etc/newsyslog.d/wazuh.conf > /dev/null << EOF
# Wazuh log rotation
/private/var/log/wazuh/*.log 644 7 1000 * J
EOF

    success "macOS logging configured"
}

# Function to configure security event monitoring
configure_security_monitoring() {
    log "Configuring security event monitoring..."

    # Enable audit logging
    sudo tee /etc/security/audit_control > /dev/null << EOF
#
# $P4: //depot/projects/trustedbsd/openbsm/etc/audit_control#8 $
#
dir:/var/audit
flags:lo,aa
minfree:5
naflags:lo,aa
policy:cnt,argv
filesz:2M
expire-after:10M
EOF

    # Start audit daemon
    sudo audit -s

    # Configure periodic security checks
    sudo tee /etc/periodic/daily/999.wazuh-security-check > /dev/null << 'EOF'
#!/bin/bash

# Wazuh daily security check for macOS
LOG_FILE="/private/var/log/wazuh/security_check.log"

echo "$(date): Starting daily security check" >> "$LOG_FILE"

# Check for suspicious processes
echo "Checking for suspicious processes..." >> "$LOG_FILE"
/bin/ps aux | grep -i "suspicious\|unknown\|malware" >> "$LOG_FILE" 2>/dev/null || echo "No suspicious processes found" >> "$LOG_FILE"

# Check network connections
echo "Checking network connections..." >> "$LOG_FILE"
/usr/sbin/netstat -an | grep -i "listen\|established" >> "$LOG_FILE"

# Check system integrity
echo "Checking system integrity..." >> "$LOG_FILE"
/usr/bin/csrutil status >> "$LOG_FILE" 2>/dev/null || echo "SIP status check failed" >> "$LOG_FILE"

# Check firewall status
echo "Checking firewall status..." >> "$LOG_FILE"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate >> "$LOG_FILE" 2>/dev/null || echo "Firewall check failed" >> "$LOG_FILE"

echo "$(date): Security check completed" >> "$LOG_FILE"
EOF

    sudo chmod +x /etc/periodic/daily/999.wazuh-security-check

    success "Security monitoring configured"
}

# Function to start services
start_services() {
    log "Starting Wazuh agent and logging services..."

    # Start Wazuh agent
    sudo /Library/Ossec/bin/ossec-control start

    # Restart syslog
    sudo killall -HUP syslogd 2>/dev/null || true

    # Check service status
    if sudo /Library/Ossec/bin/ossec-control status | grep -q "wazuh-agent is running"; then
        success "Wazuh agent is running"
    else
        error "Wazuh agent failed to start"
        return 1
    fi

    success "Services started successfully"
}

# Function to verify configuration
verify_configuration() {
    log "Verifying macOS logging configuration..."

    # Check Wazuh agent
    if sudo /Library/Ossec/bin/agent_control -l | grep -q "Active"; then
        success "Wazuh agent connected to manager"
    else
        warning "Wazuh agent not connected to manager"
    fi

    # Check log files
    local log_files=(
        "/private/var/log/system.log"
        "/private/var/log/install.log"
        "/private/var/log/wazuh/unified.log"
    )

    for log_file in "${log_files[@]}"; do
        if [ -f "$log_file" ]; then
            success "Log file exists: $log_file"
        else
            warning "Log file not found: $log_file"
        fi
    done

    # Check launch daemon
    if sudo launchctl list | grep -q "com.wazuh.logging"; then
        success "Wazuh logging launch daemon loaded"
    else
        warning "Wazuh logging launch daemon not loaded"
    fi

    # Test log forwarding
    logger -p local0.info "Wazuh macOS logging test"
    sleep 2

    if grep -q "Wazuh macOS logging test" /private/var/log/system.log 2>/dev/null; then
        success "Local logging working"
    else
        warning "Local logging test failed"
    fi

    success "Configuration verification completed"
}

# Function to display usage information
show_usage() {
    echo "macOS Logging Setup Script"
    echo "=========================="
    echo ""
    echo "This script configures macOS systems to forward logs to Wazuh manager."
    echo ""
    echo "Usage:"
    echo "  $0 <wazuh_manager_ip>"
    echo ""
    echo "Arguments:"
    echo "  wazuh_manager_ip    IP address of the Wazuh manager"
    echo ""
    echo "Example:"
    echo "  $0 192.168.1.100"
    echo ""
    echo "The script will:"
    echo "  - Install Wazuh agent for macOS"
    echo "  - Configure system logging to forward to Wazuh"
    echo "  - Set up unified logging for macOS 10.12+"
    echo "  - Configure security event monitoring"
    echo "  - Start all necessary services"
}

# Main function
main() {
    local manager_ip=$1

    if [[ -z "$manager_ip" ]]; then
        show_usage
        exit 1
    fi

    echo "macOS Logging Setup Script"
    echo "=========================="

    check_macos
    install_wazuh_agent_macos "$manager_ip"
    configure_macos_logging
    configure_security_monitoring
    start_services
    verify_configuration

    success "macOS logging setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Verify agent connection: sudo /Library/Ossec/bin/agent_control -l"
    echo "2. Check logs: tail -f /private/var/log/wazuh/*.log"
    echo "3. Monitor alerts on Wazuh dashboard"
    echo "4. Review security checks: cat /private/var/log/wazuh/security_check.log"
}

# Run main function with arguments
main "$@"