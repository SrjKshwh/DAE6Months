#!/bin/bash

# Evidence Collection Script for GRC Portal IR Environment
# This script implements automated evidence preservation procedures

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
        error "This script must be run as root for evidence collection"
        exit 1
    fi
}

# Install required forensic tools
install_forensic_tools() {
    log "Installing forensic tools..."

    # Update package list
    apt update

    # Install core forensic tools
    apt install -y dc3dd sleuthkit tcpdump wireshark-common tshark ngrep

    # Install memory analysis tools
    apt install -y volatility volatility-tools python3-volatility li-me

    # Install additional dependencies
    apt install -y python3-pip python3-dev build-essential

    # Install Python packages
    pip3 install --user openpyxl pycrypto yara-python

    log "Forensic tools installed successfully"
}

# Create evidence directory structure
create_evidence_structure() {
    local case_number="$1"

    EVIDENCE_DIR="/evidence/case_$case_number"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    log "Creating evidence directory structure for case: $case_number"

    # Create main directories
    mkdir -p "$EVIDENCE_DIR"/{disk_images,memory_dumps,network_captures,file_artifacts,logs,system_info,chain_of_custody}

    # Create subdirectories
    mkdir -p "$EVIDENCE_DIR/file_artifacts"/{browser_artifacts,recent_files,bash_history,ssh_keys}
    mkdir -p "$EVIDENCE_DIR/network_captures"/{connections,arp_tables,dns_queries}
    mkdir -p "$EVIDENCE_DIR/system_info"/{processes,users,services,configurations}

    # Initialize chain of custody log
    cat > "$EVIDENCE_DIR/chain_of_custody/custody_log.txt" << EOF
Chain of Custody Log - Case $case_number
=====================================

Case Number: $case_number
Collection Date: $(date)
Collector: $(whoami)
Hostname: $(hostname)
Tool Version: evidence_collection.sh v1.0

Evidence Collection Timeline:
EOF

    log "Evidence structure created at: $EVIDENCE_DIR"
}

# Collect system information
collect_system_info() {
    local evidence_dir="$1"

    log "Collecting system information..."

    # System details
    uname -a > "$evidence_dir/system_info/system_details.txt"
    lsb_release -a >> "$evidence_dir/system_info/system_details.txt" 2>/dev/null

    # Running processes
    ps aux > "$evidence_dir/system_info/processes.txt"

    # System services
    systemctl list-units --type=service --state=active > "$evidence_dir/system_info/services.txt"

    # User accounts
    cat /etc/passwd > "$evidence_dir/system_info/user_accounts.txt"
    getent shadow > "$evidence_dir/system_info/user_accounts.txt" 2>/dev/null || echo "Shadow file requires additional permissions" >> "$evidence_dir/system_info/user_accounts.txt"

    # System logs (copy recent logs)
    cp -r /var/log "$evidence_dir/system_info/" 2>/dev/null || warning "Could not copy system logs"

    # Network configuration
    ip addr show > "$evidence_dir/system_info/network_config.txt"
    ip route show >> "$evidence_dir/system_info/network_config.txt"
    iptables -L -n >> "$evidence_dir/system_info/network_config.txt"

    update_custody_log "$evidence_dir" "System information collected"
    log "System information collected"
}

# Collect file system artifacts
collect_file_artifacts() {
    local evidence_dir="$1"

    log "Collecting file system artifacts..."

    # Browser artifacts
    if [ -d /home/*/.mozilla/firefox ]; then
        find /home -maxdepth 3 -name ".mozilla" -type d -exec cp -r {} "$evidence_dir/file_artifacts/browser_artifacts/" \; 2>/dev/null
    fi

    if [ -d /home/*/.config/google-chrome ]; then
        find /home -maxdepth 3 -name "google-chrome" -type d -exec cp -r {} "$evidence_dir/file_artifacts/browser_artifacts/" \; 2>/dev/null
    fi

    # Recent files (modified in last 7 days)
    find /home -type f -mtime -7 -exec cp {} "$evidence_dir/file_artifacts/recent_files/" \; 2>/dev/null

    # Bash history files
    find /home -name ".bash_history" -exec cp {} "$evidence_dir/file_artifacts/bash_history/" \; 2>/dev/null
    cp /root/.bash_history "$evidence_dir/file_artifacts/bash_history/" 2>/dev/null

    # SSH keys and known hosts
    find /home -name ".ssh" -type d -exec cp -r {} "$evidence_dir/file_artifacts/ssh_keys/" \; 2>/dev/null

    # System configuration files
    cp /etc/passwd "$evidence_dir/file_artifacts/" 2>/dev/null
    cp /etc/shadow "$evidence_dir/file_artifacts/" 2>/dev/null
    cp /etc/sudoers "$evidence_dir/file_artifacts/" 2>/dev/null

    update_custody_log "$evidence_dir" "File system artifacts collected"
    log "File artifacts collected"
}

# Collect memory dump
collect_memory_dump() {
    local evidence_dir="$1"

    log "Collecting memory dump..."

    # Try LiME first
    if [ -f /usr/lib/modules/$(uname -r)/kernel/drivers/misc/lime.ko ] || [ -f ./lime.ko ]; then
        insmod /usr/lib/modules/$(uname -r)/kernel/drivers/misc/lime.ko "path=$evidence_dir/memory_dumps/memory_dump_$TIMESTAMP.lime format=lime" 2>/dev/null || \
        insmod ./lime.ko "path=$evidence_dir/memory_dumps/memory_dump_$TIMESTAMP.lime format=lime" 2>/dev/null || \
        warning "LiME memory dump failed"
    else
        warning "LiME kernel module not found"
    fi

    # Fallback to /dev/mem if available
    if [ -r /dev/mem ]; then
        dd if=/dev/mem of="$evidence_dir/memory_dumps/memory_dump_$TIMESTAMP.raw" bs=1M count=1024 2>/dev/null || warning "Raw memory dump failed"
    else
        warning "Memory dump not available - /dev/mem not accessible"
    fi

    update_custody_log "$evidence_dir" "Memory dump attempted"
    log "Memory dump collection attempted"
}

# Collect network traffic
collect_network_traffic() {
    local evidence_dir="$1"

    log "Collecting network traffic..."

    # Capture live network traffic for 30 seconds
    timeout 30 tcpdump -i any -w "$evidence_dir/network_captures/network_capture_$TIMESTAMP.pcap" 2>/dev/null || warning "Network capture failed"

    # Current network connections
    netstat -tuln > "$evidence_dir/network_captures/connections/active_connections.txt"
    ss -tuln >> "$evidence_dir/network_captures/connections/active_connections.txt"

    # ARP table
    arp -a > "$evidence_dir/network_captures/arp_tables/arp_table.txt"

    # DNS queries (if tcpdump captured any)
    if [ -f "$evidence_dir/network_captures/network_capture_$TIMESTAMP.pcap" ]; then
        tshark -r "$evidence_dir/network_captures/network_capture_$TIMESTAMP.pcap" -T fields -e dns.qry.name -e dns.a 2>/dev/null | head -50 > "$evidence_dir/network_captures/dns_queries/dns_analysis.txt" || warning "DNS analysis failed"
    fi

    update_custody_log "$evidence_dir" "Network traffic collected"
    log "Network traffic collection completed"
}

# Perform disk imaging
perform_disk_imaging() {
    local evidence_dir="$1"
    local source_device="$2"

    if [ -z "$source_device" ]; then
        warning "No source device specified for disk imaging"
        return
    fi

    log "Performing disk imaging of: $source_device"

    local image_file="$evidence_dir/disk_images/disk_image_$TIMESTAMP.dd"

    # Use dc3dd if available, otherwise dd
    if command -v dc3dd >/dev/null 2>&1; then
        dc3dd if="$source_device" of="$image_file" hash=sha256 log="$evidence_dir/disk_images/imaging_log.txt"
    else
        dd if="$source_device" of="$image_file" bs=4M status=progress
        sha256sum "$image_file" > "$image_file.sha256"
    fi

    update_custody_log "$evidence_dir" "Disk imaging completed for $source_device"
    log "Disk imaging completed"
}

# Generate integrity hashes
generate_integrity_hashes() {
    local evidence_dir="$1"

    log "Generating integrity hashes..."

    # Generate SHA256 hashes for all collected files
    find "$evidence_dir" -type f -exec sha256sum {} \; > "$evidence_dir/integrity_hashes.sha256"

    update_custody_log "$evidence_dir" "Integrity hashes generated"
    log "Integrity hashes generated"
}

# Update chain of custody log
update_custody_log() {
    local evidence_dir="$1"
    local action="$2"

    echo "$(date +'%Y-%m-%d %H:%M:%S'): $action by $(whoami) on $(hostname)" >> "$evidence_dir/chain_of_custody/custody_log.txt"
}

# Verify evidence integrity
verify_integrity() {
    local evidence_dir="$1"

    log "Verifying evidence integrity..."

    if [ -f "$evidence_dir/integrity_hashes.sha256" ]; then
        cd "$evidence_dir"
        sha256sum -c integrity_hashes.sha256 2>/dev/null | grep -E "(OK|FAILED)" || warning "Some files failed integrity check"
        log "Integrity verification completed"
    else
        warning "No integrity hash file found for verification"
    fi
}

# Generate evidence report
generate_report() {
    local evidence_dir="$1"
    local case_number="$2"

    log "Generating evidence collection report..."

    local report_file="$evidence_dir/evidence_report.txt"

    cat > "$report_file" << EOF
Evidence Collection Report - Case $case_number
==========================================

Case Number: $case_number
Collection Date: $(date)
Collector: $(whoami)
System: $(hostname)

COLLECTED EVIDENCE SUMMARY:
==========================

System Information:
$(ls -la "$evidence_dir/system_info/" | wc -l) files collected

File Artifacts:
$(find "$evidence_dir/file_artifacts/" -type f | wc -l) files collected

Memory Dumps:
$(ls -la "$evidence_dir/memory_dumps/" | grep -v "^total" | wc -l) dumps collected

Network Captures:
$(ls -la "$evidence_dir/network_captures/" | grep -v "^d" | wc -l) captures collected

Disk Images:
$(ls -la "$evidence_dir/disk_images/" | grep -v "^d" | wc -l) images created

INTEGRITY VERIFICATION:
======================
$(if [ -f "$evidence_dir/integrity_hashes.sha256" ]; then echo "SHA256 hashes generated for all files"; else echo "No integrity verification performed"; fi)

CHAIN OF CUSTODY:
================
$(cat "$evidence_dir/chain_of_custody/custody_log.txt")

This report was automatically generated by evidence_collection.sh
EOF

    log "Evidence report generated: $report_file"
}

# Main execution
main() {
    local case_number="$1"
    local source_device="$2"

    if [ -z "$case_number" ]; then
        error "Case number is required"
        echo "Usage: $0 <case_number> [source_device]"
        echo "Example: $0 CASE_001 /dev/sda"
        exit 1
    fi

    log "Starting automated evidence collection for Case $case_number"

    check_root
    install_forensic_tools
    create_evidence_structure "$case_number"

    collect_system_info "$EVIDENCE_DIR"
    collect_file_artifacts "$EVIDENCE_DIR"
    collect_memory_dump "$EVIDENCE_DIR"
    collect_network_traffic "$EVIDENCE_DIR"

    if [ -n "$source_device" ]; then
        perform_disk_imaging "$EVIDENCE_DIR" "$source_device"
    fi

    generate_integrity_hashes "$EVIDENCE_DIR"
    verify_integrity "$EVIDENCE_DIR"
    generate_report "$EVIDENCE_DIR" "$case_number"

    log "Evidence collection completed for Case $case_number"
    info "Evidence stored in: $EVIDENCE_DIR"
    info "Chain of custody: $EVIDENCE_DIR/chain_of_custody/custody_log.txt"
    info "Integrity hashes: $EVIDENCE_DIR/integrity_hashes.sha256"
    info "Evidence report: $EVIDENCE_DIR/evidence_report.txt"
}

# Show usage if no arguments
if [ $# -eq 0 ]; then
    echo "Evidence Collection Script for GRC Portal IR Environment"
    echo "======================================================"
    echo ""
    echo "This script performs comprehensive evidence collection for incident response."
    echo ""
    echo "Usage:"
    echo "  $0 <case_number> [source_device]"
    echo ""
    echo "Arguments:"
    echo "  case_number    Unique identifier for the case (required)"
    echo "  source_device  Device to image (optional, e.g., /dev/sda)"
    echo ""
    echo "Examples:"
    echo "  $0 CASE_001                    # Collect volatile evidence only"
    echo "  $0 CASE_002 /dev/sda          # Collect all evidence including disk image"
    echo ""
    echo "Evidence is stored in /evidence/case_<case_number>/"
    echo ""
    exit 0
fi

# Run main function
main "$@"