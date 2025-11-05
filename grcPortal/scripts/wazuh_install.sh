#!/bin/bash

# Wazuh Installation and Configuration Script for Parrot OS
# This script installs and configures Wazuh Manager and Agent on Parrot OS

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
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root"
    exit 1
fi

# Function to install Wazuh Manager
install_wazuh_manager() {
    log "Installing Wazuh Manager..."

    # Update system
    apt update && apt upgrade -y

    # Install dependencies
    apt install -y curl apt-transport-https lsb-release gnupg2

    # Add Wazuh repository
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

    # Update package lists
    apt update

    # Install Wazuh manager
    apt install -y wazuh-manager

    # Start and enable service
    systemctl start wazuh-manager
    systemctl enable wazuh-manager

    success "Wazuh Manager installed successfully"
}

# Function to install Wazuh Agent
install_wazuh_agent() {
    local manager_ip=$1

    if [[ -z "$manager_ip" ]]; then
        error "Manager IP is required for agent installation"
        exit 1
    fi

    log "Installing Wazuh Agent..."

    # Download and install agent
    wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.3.10-1_amd64.deb
    dpkg -i wazuh-agent_4.3.10-1_amd64.deb

    # Configure agent
    cat > /var/ossec/etc/ossec.conf << EOF
<ossec_config>
  <client>
    <server>
      <address>$manager_ip</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>debian, debian10</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
  </client>

  <!-- Log collection configuration -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kern.log</location>
  </localfile>
</ossec_config>
EOF

    # Register agent
    /var/ossec/bin/manage_agents -i $manager_ip

    # Start agent
    systemctl start wazuh-agent
    systemctl enable wazuh-agent

    success "Wazuh Agent installed and configured"
}

# Function to create custom alert rules
create_custom_rules() {
    log "Creating custom alert rules..."

    cat > /var/ossec/etc/rules/local_rules.xml << EOF
<group name="custom_rules,">
  <!-- Rule 1: Failed SSH Authentication -->
  <rule id="100001" level="10">
    <if_sid>5710</if_sid>
    <match>Failed password</match>
    <description>Failed SSH authentication attempt</description>
    <group>authentication_failures,</group>
  </rule>

  <!-- Rule 2: Suspicious File Access -->
  <rule id="100002" level="12">
    <if_sid>550</if_sid>
    <match>access|read|write</match>
    <description>Suspicious file access detected</description>
    <group>file_access,policy_violation</group>
  </rule>

  <!-- Rule 3: Network Anomaly -->
  <rule id="100003" level="8">
    <if_sid>530</if_sid>
    <match>connection refused|timeout</match>
    <description>Network connection anomaly detected</description>
    <group>network,anomaly</group>
  </rule>

  <!-- Advanced Rules -->
  <rule id="100004" level="15">
    <if_sid>100001</if_sid>
    <match>invalid user</match>
    <timeframe>600</timeframe>
    <frequency>5</frequency>
    <description>Multiple failed SSH login attempts from invalid users</description>
    <group>brute_force,authentication_failures</group>
  </rule>

  <rule id="100005" level="13">
    <if_sid>100002</if_sid>
    <match>/etc/passwd|/etc/shadow|/etc/sudoers</match>
    <description>Access to sensitive system files</description>
    <group>privilege_escalation,file_access</group>
  </rule>

  <rule id="100006" level="11">
    <if_sid>100003</if_sid>
    <srcip>!192.168.1.0/24</srcip>
    <description>Suspicious external network connection</description>
    <group>network,external_threat</group>
  </rule>
</group>
EOF

    # Restart Wazuh manager to load new rules
    systemctl restart wazuh-manager

    success "Custom alert rules created and loaded"
}

# Function to configure log collection
configure_logging() {
    log "Configuring enhanced logging..."

    # Ensure rsyslog is running
    systemctl start rsyslog
    systemctl enable rsyslog

    # Create Wazuh log directory
    mkdir -p /var/log/wazuh

    # Configure rsyslog for Wazuh
    cat > /etc/rsyslog.d/50-wazuh.conf << EOF
# Wazuh log collection
*.* @@localhost:514

# Local logging with high precision
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
\$FileOwner root
\$FileGroup adm
\$FileCreateMode 0640
\$DirCreateMode 0755
\$Umask 0022

# Custom logging rules
if \$programname == 'sshd' then /var/log/wazuh/sshd.log
if \$programname == 'sudo' then /var/log/wazuh/sudo.log
if \$programname == 'iptables' then /var/log/wazuh/firewall.log
EOF

    # Configure logrotate
    cat > /etc/logrotate.d/wazuh-custom << EOF
/var/log/wazuh/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    postrotate
        systemctl reload rsyslog
    endscript
}
EOF

    # Restart services
    systemctl restart rsyslog
    systemctl restart wazuh-manager

    success "Enhanced logging configured"
}

# Function to verify installation
verify_installation() {
    log "Verifying installation..."

    # Check services
    if systemctl is-active --quiet wazuh-manager; then
        success "Wazuh Manager is running"
    else
        error "Wazuh Manager is not running"
        return 1
    fi

    if systemctl is-active --quiet wazuh-agent; then
        success "Wazuh Agent is running"
    else
        warning "Wazuh Agent is not running (expected for manager-only setup)"
    fi

    # Check agent connections
    agent_count=$(/var/ossec/bin/agent_control -l | grep -c "Active")
    success "Active agents: $agent_count"

    # Test rules
    if /var/ossec/bin/ossec-logtest -f /var/ossec/etc/rules/local_rules.xml >/dev/null 2>&1; then
        success "Custom rules are valid"
    else
        error "Custom rules have syntax errors"
        return 1
    fi

    # Check log collection
    if [ -f /var/log/wazuh/sshd.log ]; then
        success "Custom log files are being created"
    else
        warning "Custom log files not yet created (will be created on events)"
    fi

    success "Installation verification completed"
}

# Main installation function
main() {
    local install_type=$1
    local manager_ip=$2

    echo "Wazuh Installation Script for Parrot OS"
    echo "========================================"

    case $install_type in
        "manager")
            log "Installing Wazuh Manager..."
            install_wazuh_manager
            create_custom_rules
            configure_logging
            ;;
        "agent")
            if [[ -z "$manager_ip" ]]; then
                error "Manager IP is required for agent installation"
                echo "Usage: $0 agent <manager_ip>"
                exit 1
            fi
            log "Installing Wazuh Agent..."
            install_wazuh_agent "$manager_ip"
            ;;
        "full")
            if [[ -z "$manager_ip" ]]; then
                manager_ip="127.0.0.1"
                warning "No manager IP provided, using localhost for full installation"
            fi
            log "Installing complete Wazuh setup..."
            install_wazuh_manager
            install_wazuh_agent "$manager_ip"
            create_custom_rules
            configure_logging
            ;;
        *)
            echo "Usage: $0 {manager|agent|full} [manager_ip]"
            echo ""
            echo "Examples:"
            echo "  $0 manager                    # Install only manager"
            echo "  $0 agent 192.168.1.100        # Install only agent"
            echo "  $0 full 192.168.1.100         # Install manager and agent"
            exit 1
            ;;
    esac

    # Verify installation
    verify_installation

    success "Wazuh installation completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Access Wazuh dashboard at https://localhost:5601"
    echo "2. Default credentials: admin/admin"
    echo "3. Monitor agent connections: /var/ossec/bin/agent_control -l"
    echo "4. Check alerts: tail -f /var/ossec/logs/alerts/alerts.log"
}

# Run main function with arguments
main "$@"