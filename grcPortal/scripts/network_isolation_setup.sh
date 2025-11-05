#!/bin/bash

# Network Isolation Setup Script for GRC Portal IR Environment
# This script implements network isolation procedures for incident response

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        exit 1
    fi
}

# Install required packages
install_dependencies() {
    log "Installing required packages..."
    apt update
    apt install -y vlan iptables-persistent net-tools iproute2
    log "Dependencies installed successfully"
}

# Configure network interfaces
configure_interfaces() {
    log "Configuring network interfaces..."

    # Backup existing interfaces file
    cp /etc/network/interfaces /etc/network/interfaces.backup.$(date +%Y%m%d_%H%M%S)

    # Create new interfaces configuration
    cat > /etc/network/interfaces << EOF
# The loopback network interface
auto lo
iface lo inet loopback

# Primary interface (NAT - internet access)
auto eth0
iface eth0 inet dhcp

# Internal network interface (isolated segment)
auto eth1
iface eth1 inet static
    address 192.168.56.10
    netmask 255.255.255.0
    network 192.168.56.0
    broadcast 192.168.56.255

# Host-only interface (management access)
auto eth2
iface eth2 inet static
    address 192.168.57.10
    netmask 255.255.255.0
    network 192.168.57.0
    broadcast 192.168.57.255
EOF

    log "Network interfaces configured"
}

# Configure UFW firewall
configure_ufw() {
    log "Configuring UFW firewall..."

    # Enable UFW
    ufw --force enable

    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH only from management interface
    ufw allow in on eth2 to any port 22 proto tcp

    # Allow Wazuh agent communication
    ufw allow in on eth1 to any port 1514 proto tcp
    ufw allow out on eth1 to any port 1514 proto tcp

    # Allow DNS resolution
    ufw allow out to any port 53 proto udp

    # Allow HTTP/HTTPS for updates (temporary)
    ufw allow out to any port 80 proto tcp
    ufw allow out to any port 443 proto tcp

    # Block suspicious ports
    ufw deny in to any port 23 proto tcp  # Telnet
    ufw deny in to any port 21 proto tcp  # FTP
    ufw deny in to any port 3389 proto tcp # RDP
    ufw deny in to any port 5900 proto tcp # VNC

    # Reload firewall
    ufw reload

    log "UFW firewall configured"
}

# Configure iptables rules
configure_iptables() {
    log "Configuring iptables rules..."

    # Create iptables rules file
    cat > /etc/iptables/rules.v4 << EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Allow loopback
-A INPUT -i lo -j ACCEPT

# Allow established connections
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from management interface only
-A INPUT -i eth2 -p tcp --dport 22 -j ACCEPT

# Allow Wazuh communication on internal network
-A INPUT -i eth1 -p tcp --dport 1514 -j ACCEPT
-A OUTPUT -o eth1 -p tcp --dport 1514 -j ACCEPT

# Allow DNS queries
-A OUTPUT -p udp --dport 53 -j ACCEPT

# Allow HTTP/HTTPS for updates
-A OUTPUT -p tcp --dport 80 -j ACCEPT
-A OUTPUT -p tcp --dport 443 -j ACCEPT

# Block suspicious inbound traffic
-A INPUT -p tcp --dport 23 -j DROP  # Telnet
-A INPUT -p tcp --dport 21 -j DROP  # FTP
-A INPUT -p tcp --dport 3389 -j DROP # RDP
-A INPUT -p tcp --dport 5900 -j DROP # VNC

# Log dropped packets
-A INPUT -j LOG --log-prefix "iptables-dropped: " --log-level 4
-A FORWARD -j LOG --log-prefix "iptables-forwarded: " --log-level 4

COMMIT
EOF

    # Apply iptables rules
    iptables-restore < /etc/iptables/rules.v4

    log "iptables rules configured"
}

# Configure VLANs
configure_vlans() {
    log "Configuring VLANs..."

    # Load 802.1q module
    modprobe 8021q

    # Make module load persistent
    echo "8021q" >> /etc/modules

    # Create VLAN interfaces
    vconfig add eth1 100  # Incident Response VLAN
    vconfig add eth1 200  # Quarantine VLAN

    # Configure VLAN interfaces
    cat >> /etc/network/interfaces << EOF

# VLAN 100 - Incident Response Network
auto eth1.100
iface eth1.100 inet static
    address 192.168.100.10
    netmask 255.255.255.0
    vlan-raw-device eth1

# VLAN 200 - Quarantine Network
auto eth1.200
iface eth1.200 inet static
    address 192.168.200.10
    netmask 255.255.255.0
    vlan-raw-device eth1
EOF

    log "VLANs configured"
}

# Configure network namespace isolation
configure_namespace() {
    log "Configuring network namespace isolation..."

    # Create quarantine namespace
    ip netns add quarantine

    # Create virtual ethernet pair
    ip link add veth-quar host type veth peer name veth-quar netns quarantine

    # Configure host side
    ip link set veth-quar up
    ip addr add 192.168.201.1/24 dev veth-quar

    # Configure quarantine namespace
    ip netns exec quarantine ip link set lo up
    ip netns exec quarantine ip link set veth-quar up
    ip netns exec quarantine ip addr add 192.168.201.2/24 dev veth-quar

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1
    iptables -t nat -A POSTROUTING -s 192.168.201.0/24 -j MASQUERADE

    # Make IP forwarding persistent
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf

    log "Network namespace isolation configured"
}

# Create network isolation scripts
create_isolation_scripts() {
    log "Creating network isolation scripts..."

    # Network isolation script
    cat > /usr/local/bin/network_isolate.sh << 'EOF'
#!/bin/bash

# Network Isolation Script for Incident Response
# Usage: ./network_isolate.sh [isolate|restore] [target_ip]

ACTION=$1
TARGET_IP=$2

case $ACTION in
    isolate)
        echo "Isolating network for incident response..."

        # Block all traffic to/from target
        sudo iptables -I INPUT -s $TARGET_IP -j DROP
        sudo iptables -I OUTPUT -d $TARGET_IP -j DROP
        sudo iptables -I FORWARD -s $TARGET_IP -j DROP
        sudo iptables -I FORWARD -d $TARGET_IP -j DROP

        # Log isolation action
        logger -p security.info "Network isolation activated for $TARGET_IP"

        echo "Network isolation complete for $TARGET_IP"
        ;;

    restore)
        echo "Restoring network connectivity..."

        # Remove isolation rules
        sudo iptables -D INPUT -s $TARGET_IP -j DROP 2>/dev/null
        sudo iptables -D OUTPUT -d $TARGET_IP -j DROP 2>/dev/null
        sudo iptables -D FORWARD -s $TARGET_IP -j DROP 2>/dev/null
        sudo iptables -D FORWARD -d $TARGET_IP -j DROP 2>/dev/null

        # Log restoration action
        logger -p security.info "Network isolation removed for $TARGET_IP"

        echo "Network connectivity restored for $TARGET_IP"
        ;;

    status)
        echo "Current network isolation status:"
        sudo iptables -L -n | grep DROP
        ;;

    *)
        echo "Usage: $0 [isolate|restore|status] [target_ip]"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/network_isolate.sh

    # Network monitoring script
    cat > /usr/local/bin/network_monitor.sh << 'EOF'
#!/bin/bash

# Network Monitoring Script for IR Environment
echo "=== Network Interface Status ==="
ip addr show

echo -e "\n=== Routing Table ==="
ip route show

echo -e "\n=== Firewall Status ==="
sudo ufw status

echo -e "\n=== iptables Rules ==="
sudo iptables -L -n

echo -e "\n=== Network Connections ==="
netstat -tuln

echo -e "\n=== ARP Table ==="
arp -n

echo -e "\n=== Network Namespaces ==="
ip netns list
EOF

    chmod +x /usr/local/bin/network_monitor.sh

    log "Network isolation scripts created"
}

# Test network configuration
test_configuration() {
    log "Testing network configuration..."

    # Restart networking
    systemctl restart networking

    # Test interface configuration
    info "Testing network interfaces..."
    ip addr show | grep -E "(eth[0-2]|inet )"

    # Test firewall
    info "Testing firewall configuration..."
    ufw status | head -10

    # Test iptables
    info "Testing iptables rules..."
    iptables -L INPUT | head -10

    # Test VLANs
    info "Testing VLAN configuration..."
    vconfig show 2>/dev/null || echo "VLANs not configured or module not loaded"

    # Test namespace
    info "Testing network namespace..."
    ip netns list

    log "Network configuration testing completed"
}

# Main execution
main() {
    log "Starting Network Isolation Setup for GRC Portal IR Environment"

    check_root
    install_dependencies
    configure_interfaces
    configure_ufw
    configure_iptables
    configure_vlans
    configure_namespace
    create_isolation_scripts
    test_configuration

    log "Network Isolation Setup completed successfully!"
    info "Available commands:"
    info "  network_isolate.sh [isolate|restore|status] [target_ip]"
    info "  network_monitor.sh"
    info "  ufw status"
    info "  iptables -L"
}

# Run main function
main "$@"