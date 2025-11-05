#!/bin/bash

# VirtualBox Network Setup Script for GRC Portal IR Environment
# This script configures VirtualBox networking for network isolation

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

# Check if VBoxManage is available
check_virtualbox() {
    if ! command -v VBoxManage &> /dev/null; then
        error "VBoxManage not found. Please install VirtualBox."
        exit 1
    fi
    log "VirtualBox found: $(VBoxManage --version)"
}

# Create host-only network
create_hostonly_network() {
    log "Creating host-only network..."

    # Check if host-only interface already exists
    if VBoxManage list hostonlyifs | grep -q "Name:"; then
        info "Host-only interface already exists"
        HOST_IFACE=$(VBoxManage list hostonlyifs | grep "Name:" | head -1 | awk '{print $2}')
    else
        # Create new host-only interface
        VBoxManage hostonlyif create
        HOST_IFACE=$(VBoxManage list hostonlyifs | grep "Name:" | head -1 | awk '{print $2}')
    fi

    # Configure host-only network
    VBoxManage hostonlyif ipconfig "$HOST_IFACE" --ip 192.168.57.1 --netmask 255.255.255.0

    log "Host-only network configured: $HOST_IFACE (192.168.57.1/24)"
}

# Create internal network
create_internal_network() {
    log "Creating internal network..."

    # Create internal network (ignore if it already exists)
    VBoxManage natnetwork add --netname "ir-internal" --network "192.168.56.0/24" --enable --dhcp off 2>/dev/null || info "Internal network already exists"

    log "Internal network configured: ir-internal (192.168.56.0/24)"
}

# Configure VM network adapters
configure_vm_network() {
    local VM_NAME="$1"

    if [ -z "$VM_NAME" ]; then
        error "VM name not provided"
        echo "Usage: $0 <vm_name>"
        exit 1
    fi

    log "Configuring network adapters for VM: $VM_NAME"

    # Check if VM exists
    if ! VBoxManage showvminfo "$VM_NAME" &> /dev/null; then
        error "VM '$VM_NAME' not found"
        exit 1
    fi

    # Get host-only interface name
    HOST_IFACE=$(VBoxManage list hostonlyifs | grep "Name:" | head -1 | awk '{print $2}')

    # Configure Adapter 1: NAT
    VBoxManage modifyvm "$VM_NAME" --nic1 nat

    # Configure Adapter 2: Internal Network
    VBoxManage modifyvm "$VM_NAME" --nic2 intnet
    VBoxManage modifyvm "$VM_NAME" --intnet2 "ir-internal"

    # Configure Adapter 3: Host-only
    VBoxManage modifyvm "$VM_NAME" --nic3 hostonly
    VBoxManage modifyvm "$VM_NAME" --hostonlyadapter3 "$HOST_IFACE"

    log "VM network adapters configured successfully"
}

# Display network configuration summary
show_network_summary() {
    log "VirtualBox Network Configuration Summary:"
    echo ""
    info "Host-only Networks:"
    VBoxManage list hostonlyifs

    echo ""
    info "NAT Networks:"
    VBoxManage list natnetworks

    echo ""
    info "Internal Networks:"
    VBoxManage list intnets

    echo ""
    info "VM Network Configuration Instructions:"
    echo "  1. Power off your VM if it's running"
    echo "  2. In VirtualBox Manager, select your VM"
    echo "  3. Go to Settings > Network"
    echo "  4. Configure adapters as follows:"
    echo "     - Adapter 1: NAT (for internet access)"
    echo "     - Adapter 2: Internal Network 'ir-internal' (for isolated communication)"
    echo "     - Adapter 3: Host-only Adapter (for host communication during IR)"
    echo ""
    info "Network IP Assignments:"
    echo "  - NAT: DHCP (automatic)"
    echo "  - Internal: 192.168.56.10/24"
    echo "  - Host-only: 192.168.57.10/24"
}

# Test network connectivity
test_network_connectivity() {
    log "Testing network connectivity..."

    # Test host-only network
    info "Testing host-only network connectivity..."
    if ping -c 2 192.168.57.1 &> /dev/null; then
        log "Host-only network connectivity: OK"
    else
        warning "Host-only network connectivity: FAILED (VM may not be running)"
    fi

    # Test internal network (will fail if no other VMs are connected)
    info "Note: Internal network connectivity requires another VM on the same network"
}

# Main execution
main() {
    local VM_NAME="$1"

    log "Starting VirtualBox Network Setup for GRC Portal IR Environment"

    check_virtualbox
    create_hostonly_network
    create_internal_network

    if [ -n "$VM_NAME" ]; then
        configure_vm_network "$VM_NAME"
    else
        warning "No VM name provided. Skipping VM network configuration."
        info "To configure a specific VM, run: $0 <vm_name>"
    fi

    show_network_summary
    test_network_connectivity

    log "VirtualBox Network Setup completed successfully!"
}

# Show usage if no arguments
if [ $# -eq 0 ]; then
    echo "VirtualBox Network Setup Script for GRC Portal IR Environment"
    echo ""
    echo "Usage:"
    echo "  $0                    # Setup networks only"
    echo "  $0 <vm_name>         # Setup networks and configure specific VM"
    echo ""
    echo "Examples:"
    echo "  $0                    # Create networks"
    echo "  $0 'Parrot OS IR'    # Create networks and configure VM"
    echo ""
    exit 0
fi

# Run main function
main "$@"