# Security Incident Response Playbooks

## Overview
This document contains standardized playbooks for responding to common security incidents in the GRC Portal environment. Each playbook provides step-by-step instructions for incident responders.

## Playbook 1: Unauthorized Access Attempt

### Detection
- Security monitoring alerts on failed login attempts
- Unusual login patterns or geographic anomalies
- Multiple authentication failures from single IP

### Immediate Response Steps
1. **Isolate the Threat**
   - Block the suspicious IP address in firewall
   - Temporarily disable affected user accounts if compromised
   - Enable enhanced logging on authentication systems

2. **Gather Evidence**
   - Collect authentication logs from affected systems
   - Document IP addresses, timestamps, and failed attempts
   - Capture screenshots of suspicious login attempts

3. **Assess Impact**
   - Determine if any unauthorized access was successful
   - Check for data exfiltration or system modifications
   - Review user account activity for anomalies

4. **Contain the Incident**
   - Implement multi-factor authentication if not already enabled
   - Change passwords for potentially compromised accounts
   - Restrict network access to critical systems

5. **Eradicate the Threat**
   - Remove any backdoors or malicious code
   - Reset all potentially affected credentials
   - Update security policies and access controls

6. **Recover Systems**
   - Restore normal access for legitimate users
   - Monitor systems for reoccurrence
   - Validate system integrity

### Lessons Learned
- Implement account lockout policies
- Regular security awareness training
- Continuous monitoring of authentication patterns

## Playbook 2: Malware Detection

### Detection
- Antivirus alerts or unusual system behavior
- Unexpected network traffic patterns
- System performance degradation
- Suspicious file modifications

### Immediate Response Steps
1. **Isolate Affected Systems**
   - Disconnect infected systems from network
   - Quarantine suspicious files
   - Disable removable media access

2. **Preserve Evidence**
   - Create forensic images of affected systems
   - Collect memory dumps and network logs
   - Document system state and running processes

3. **Assess Infection Scope**
   - Scan all connected systems for similar indicators
   - Check for data exfiltration attempts
   - Review backup integrity

4. **Contain the Malware**
   - Implement network segmentation
   - Block malicious command and control servers
   - Disable compromised user accounts

5. **Eradicate the Malware**
   - Run comprehensive antivirus scans
   - Remove identified malicious files
   - Clean system registries and startup entries
   - Update all security signatures

6. **Recovery and Monitoring**
   - Restore systems from clean backups
   - Monitor for reinfection attempts
   - Update endpoint protection software

### Lessons Learned
- Regular system updates and patch management
- User education on phishing and safe computing
- Implementation of application whitelisting

## Playbook 3: Data Breach Incident

### Detection
- Unusual data access patterns
- Security monitoring alerts
- User reports of suspicious activity
- Database integrity checks failing

### Immediate Response Steps
1. **Stop the Breach**
   - Revoke access for suspicious accounts
   - Implement database access restrictions
   - Enable audit logging on all data access

2. **Assess Data Exposure**
   - Identify what data was accessed or exfiltrated
   - Determine the breach timeline
   - Assess potential impact on affected individuals

3. **Notify Stakeholders**
   - Inform executive leadership
   - Prepare regulatory notifications
   - Communicate with affected customers/users

4. **Contain Data Loss**
   - Encrypt sensitive data at rest
   - Implement data loss prevention controls
   - Restrict data export capabilities

5. **Eradicate Vulnerabilities**
   - Patch exploited vulnerabilities
   - Update access controls and permissions
   - Implement additional monitoring controls

6. **Recovery and Prevention**
   - Restore systems from clean backups
   - Implement enhanced encryption
   - Conduct security awareness training

### Lessons Learned
- Regular vulnerability assessments
- Implementation of data classification and labeling
- Enhanced monitoring and alerting

## Playbook 4: Denial of Service Attack

### Detection
- System performance degradation
- Network traffic spikes
- Service unavailability alerts
- Unusual CPU or memory usage

### Immediate Response Steps
1. **Implement Traffic Filtering**
   - Enable DDoS protection services
   - Block suspicious IP addresses
   - Implement rate limiting

2. **Scale Resources**
   - Activate backup systems
   - Increase server capacity
   - Distribute load across multiple systems

3. **Preserve Evidence**
   - Collect network traffic logs
   - Document attack patterns
   - Capture system performance metrics

4. **Contain the Attack**
   - Isolate affected network segments
   - Implement traffic scrubbing
   - Update firewall rules

5. **Eradicate Attack Vectors**
   - Block attack source IP ranges
   - Update intrusion prevention systems
   - Implement geo-blocking if applicable

6. **Recovery and Hardening**
   - Restore normal service levels
   - Implement additional DDoS protections
   - Update incident response procedures

### Lessons Learned
- Regular capacity planning and stress testing
- Implementation of CDN and load balancing
- Development of DDoS response procedures

## General Playbook Guidelines

### Communication
- Establish clear communication channels
- Keep stakeholders informed of progress
- Document all actions and decisions

### Evidence Handling
- Maintain chain of custody for all evidence
- Use write-protected media for evidence storage
- Document all evidence collection procedures

### Documentation
- Record all actions taken during response
- Document lessons learned and improvements
- Update playbooks based on experience

### Testing and Maintenance
- Regularly test playbook procedures
- Update playbooks based on new threats
- Conduct training exercises

## Escalation Procedures

### When to Escalate
- Incident exceeds responder capabilities
- Legal or regulatory implications
- Significant business impact
- External assistance required

### Escalation Contacts
- Security Team Lead: security-lead@grcportal.com
- IT Director: it-director@grcportal.com
- Legal Counsel: legal@grcportal.com
- External Forensics: forensics@partner.com

## Continuous Improvement

After each incident:
1. Conduct post-incident review
2. Identify areas for improvement
3. Update playbooks and procedures
4. Provide additional training
5. Implement preventive measures

## Playbook 5: Containment Procedures for Compromised Systems

### Overview
This containment playbook provides systematic procedures for isolating compromised hosts, blocking malicious network traffic, and shutting down affected services during incident response. It focuses on VirtualBox-based isolation techniques suitable for the GRC Portal IR environment.

### Detection Triggers
- Malware detection alerts
- Unauthorized access attempts
- Suspicious network traffic patterns
- System integrity violations
- Unusual service behavior

### Immediate Containment Actions

#### Phase 1: Host Isolation in VirtualBox Environment

##### 1.1 Virtual Machine Isolation
**Objective:** Immediately isolate the compromised VM from network connectivity

**VirtualBox Manager Steps:**
```bash
# Power off the VM immediately (if safe to do so)
VBoxManage controlvm "Compromised-VM" acpipowerbutton

# Disconnect all network adapters
VBoxManage modifyvm "Compromised-VM" --nic1 null
VBoxManage modifyvm "Compromised-VM" --nic2 null
VBoxManage modifyvm "Compromised-VM" --nic3 null

# Create isolated snapshot for analysis
VBoxManage snapshot "Compromised-VM" take "CONTAINMENT_SNAPSHOT_$(date +%Y%m%d_%H%M%S)" --description "Containment snapshot - isolated from network"
```

**Alternative: Runtime Isolation (if VM must remain running)**
```bash
# Disconnect network interfaces while VM is running
VBoxManage controlvm "Compromised-VM" setlinkstate1 off
VBoxManage controlvm "Compromised-VM" setlinkstate2 off
VBoxManage controlvm "Compromised-VM" setlinkstate3 off

# Enable host-only adapter for management access only
VBoxManage modifyvm "Compromised-VM" --nic1 hostonly
VBoxManage modifyvm "Compromised-VM" --hostonlyadapter1 "vboxnet0"
```

##### 1.2 Host-Level Isolation Procedures
**Objective:** Prevent lateral movement within the host system

**Network Interface Isolation:**
```bash
# Identify compromised system's network interfaces
ip link show

# Disable network interfaces (replace eth0 with actual interface)
sudo ip link set eth0 down

# Remove IP addresses from interfaces
sudo ip addr flush dev eth0

# Disable network manager for the interface
sudo nmcli device set eth0 managed no
```

**Routing Table Manipulation:**
```bash
# Backup current routing table
ip route show > /tmp/routing_backup_$(date +%s)

# Remove default gateway to prevent outbound connectivity
sudo ip route del default

# Add route to management network only (if needed)
sudo ip route add 192.168.57.0/24 via 192.168.57.1 dev eth2
```

#### Phase 2: Network Traffic Blocking

##### 2.1 Firewall-Based Containment
**Objective:** Block malicious traffic patterns and isolate affected systems

**UFW Immediate Blocking:**
```bash
# Block specific malicious IP addresses
sudo ufw deny from 192.168.1.100
sudo ufw deny from 10.0.0.50

# Block suspicious port ranges
sudo ufw deny 3389/tcp  # RDP
sudo ufw deny 5900/tcp  # VNC
sudo ufw deny 23/tcp    # Telnet

# Block outbound connections to known C2 servers
sudo ufw deny out to 203.0.113.1
sudo ufw deny out to malicious-domain.com

# Reload firewall rules
sudo ufw reload
```

**Advanced iptables Containment:**
```bash
# Create containment chain
sudo iptables -N CONTAINMENT

# Block all traffic to/from compromised IP
sudo iptables -I CONTAINMENT -s 192.168.1.100 -j DROP
sudo iptables -I CONTAINMENT -d 192.168.1.100 -j DROP

# Block suspicious protocols
sudo iptables -I CONTAINMENT -p tcp --dport 4444 -j DROP  # Common C2 port
sudo iptables -I CONTAINMENT -p udp --dport 53 -d 8.8.8.8 -j DROP  # Block DNS to suspicious servers

# Insert containment rules at top of chains
sudo iptables -I INPUT -j CONTAINMENT
sudo iptables -I OUTPUT -j CONTAINMENT
sudo iptables -I FORWARD -j CONTAINMENT

# Log containment actions
sudo iptables -I CONTAINMENT -j LOG --log-prefix "CONTAINMENT: " --log-level 4
```

##### 2.2 Network Segmentation Enforcement
**Objective:** Implement immediate network segmentation

**VLAN Isolation:**
```bash
# Move compromised system to quarantine VLAN
sudo vconfig add eth1 200  # Quarantine VLAN
sudo ifconfig eth1.200 192.168.200.10 netmask 255.255.255.0 up

# Remove from production VLAN
sudo ifconfig eth1.100 down
sudo vconfig rem eth1.100
```

**Network Namespace Isolation:**
```bash
# Create quarantine network namespace
sudo ip netns add quarantine_ns

# Move compromised processes to quarantine namespace (advanced technique)
# Note: This requires process migration tools and is system-specific

# Create isolated network interface
sudo ip link add veth-quar type veth peer name veth-quar-peer
sudo ip link set veth-quar netns quarantine_ns
sudo ip netns exec quarantine_ns ip link set veth-quar up
sudo ip netns exec quarantine_ns ip addr add 192.168.201.2/24 dev veth-quar
```

#### Phase 3: Service Shutdown Procedures

##### 3.1 Critical Service Identification
**Objective:** Identify and safely shut down compromised services

**Service Inventory:**
```bash
# List all running services
systemctl list-units --type=service --state=running

# Check for suspicious services
ps aux | grep -E "(apache|nginx|mysql|postgres|ssh|ftp)" | grep -v grep

# Identify listening ports
netstat -tlnp | grep LISTEN
```

##### 3.2 Controlled Service Shutdown
**Objective:** Shut down services while preserving evidence

**Web Services:**
```bash
# Stop web servers gracefully
sudo systemctl stop apache2
sudo systemctl stop nginx

# Kill any remaining web processes
sudo pkill -9 apache2
sudo pkill -9 nginx
```

**Database Services:**
```bash
# Stop database services
sudo systemctl stop mysql
sudo systemctl stop postgresql

# Create database dumps before shutdown (if safe)
sudo mysqldump --all-databases > /evidence/database_backup_$(date +%s).sql
```

**Remote Access Services:**
```bash
# Disable SSH access (but keep service running for management)
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo systemctl reload ssh

# Alternative: Complete SSH shutdown
sudo systemctl stop ssh
```

**Mail Services:**
```bash
# Stop mail services
sudo systemctl stop postfix
sudo systemctl stop dovecot
sudo systemctl stop sendmail
```

##### 3.3 Process Termination
**Objective:** Terminate malicious processes safely

**Process Analysis:**
```bash
# Identify suspicious processes
ps aux | head -20
ps aux | grep -i "suspicious\|malware\|unknown"

# Check for root processes
ps aux | grep root | head -10

# Monitor process creation
sudo sysdig -c spy_processes
```

**Safe Process Termination:**
```bash
# Terminate specific processes gracefully
sudo kill -TERM <PID>

# Force kill if necessary
sudo kill -9 <PID>

# Kill all processes for a specific user
sudo pkill -u compromised_user

# Kill processes by name
sudo pkill -9 suspicious_process
```

#### Phase 4: Containment Verification

##### 4.1 Isolation Verification
**Objective:** Confirm containment effectiveness

**Network Isolation Check:**
```bash
# Verify network interfaces are down
ip link show | grep -E "(eth0|eth1)"

# Check routing table
ip route show

# Test connectivity (should fail)
ping -c 1 8.8.8.8
curl -I https://www.google.com
```

**Firewall Verification:**
```bash
# Check UFW status
sudo ufw status verbose

# Verify iptables rules
sudo iptables -L -n | grep DROP

# Test blocked connections
telnet blocked-ip 80
```

##### 4.2 Service Shutdown Verification
**Objective:** Confirm services are properly shut down

**Service Status Check:**
```bash
# Verify services are stopped
systemctl status apache2
systemctl status mysql
systemctl status ssh

# Check for remaining processes
ps aux | grep apache2
ps aux | grep mysql
```

#### Phase 5: Evidence Preservation During Containment

##### 5.1 Containment Logging
**Objective:** Document all containment actions

**Containment Log Creation:**
```bash
# Create containment log
CONTAINMENT_LOG="/evidence/containment_log_$(date +%Y%m%d_%H%M%S).txt"

cat > "$CONTAINMENT_LOG" << EOF
CONTAINMENT LOG - Case $(date +%Y%m%d_%H%M%S)
==========================================

Containment Start Time: $(date)
Containment Officer: $(whoami)
System: $(hostname)

CONTAINMENT ACTIONS TAKEN:
========================

1. VirtualBox Isolation:
   - VM powered off: $(date)
   - Network adapters disconnected: $(date)
   - Snapshot created: CONTAINMENT_SNAPSHOT_$(date +%Y%m%d_%H%M%S)

2. Network Blocking:
   - IPs blocked: [list blocked IPs]
   - Ports blocked: [list blocked ports]
   - Firewall rules applied: $(date)

3. Service Shutdown:
   - Services stopped: [list stopped services]
   - Processes terminated: [list terminated processes]
   - Shutdown time: $(date)

VERIFICATION RESULTS:
===================

Network Isolation: [PASS/FAIL]
Service Shutdown: [PASS/FAIL]
Evidence Preservation: [PASS/FAIL]

ADDITIONAL NOTES:
================
[Containment officer notes]
EOF

echo "Containment log created: $CONTAINMENT_LOG"
```

### Automated Containment Script

#### Containment Automation Tool
```bash
# Create automated containment script
sudo tee /usr/local/bin/containment_playbook.sh << 'EOF'
#!/bin/bash

# Automated Containment Playbook for Incident Response
# Usage: ./containment_playbook.sh [vm_name] [case_number]

VM_NAME=$1
CASE_NUMBER=${2:-"AUTO_$(date +%Y%m%d_%H%M%S)"}

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Phase 1: Host Isolation
isolate_host() {
    log "Phase 1: Initiating host isolation for VM: $VM_NAME"

    if [ -z "$VM_NAME" ]; then
        error "VM name required for isolation"
        return 1
    fi

    # Check if VM exists
    if ! VBoxManage showvminfo "$VM_NAME" &>/dev/null; then
        error "VM '$VM_NAME' not found"
        return 1
    fi

    # Power off VM
    log "Powering off VM..."
    VBoxManage controlvm "$VM_NAME" acpipowerbutton 2>/dev/null || VBoxManage controlvm "$VM_NAME" poweroff

    # Wait for shutdown
    sleep 10

    # Disconnect network interfaces
    log "Disconnecting network interfaces..."
    VBoxManage modifyvm "$VM_NAME" --nic1 null
    VBoxManage modifyvm "$VM_NAME" --nic2 null
    VBoxManage modifyvm "$VM_NAME" --nic3 null

    # Create containment snapshot
    SNAPSHOT_NAME="CONTAINMENT_${CASE_NUMBER}_$(date +%Y%m%d_%H%M%S)"
    VBoxManage snapshot "$VM_NAME" take "$SNAPSHOT_NAME" --description "Containment snapshot - network isolated"

    log "Host isolation completed"
}

# Phase 2: Network Traffic Blocking
block_network_traffic() {
    log "Phase 2: Implementing network traffic blocking"

    # Create containment iptables chain
    sudo iptables -t filter -N CONTAINMENT 2>/dev/null || true

    # Block common malicious IPs (example IPs - replace with actual threats)
    sudo iptables -I CONTAINMENT -s 192.168.1.100 -j DROP
    sudo iptables -I CONTAINMENT -d 192.168.1.100 -j DROP

    # Block suspicious ports
    sudo iptables -I CONTAINMENT -p tcp --dport 4444 -j DROP  # Common C2
    sudo iptables -I CONTAINMENT -p tcp --dport 3389 -j DROP  # RDP
    sudo iptables -I CONTAINMENT -p tcp --dport 5900 -j DROP  # VNC

    # Insert containment rules
    sudo iptables -I INPUT -j CONTAINMENT
    sudo iptables -I OUTPUT -j CONTAINMENT
    sudo iptables -I FORWARD -j CONTAINMENT

    # Log containment actions
    sudo iptables -I CONTAINMENT -j LOG --log-prefix "CONTAINMENT: " --log-level 4

    # UFW blocking as backup
    sudo ufw deny 3389/tcp 2>/dev/null
    sudo ufw deny 5900/tcp 2>/dev/null
    sudo ufw deny 4444/tcp 2>/dev/null

    log "Network traffic blocking implemented"
}

# Phase 3: Service Shutdown
shutdown_services() {
    log "Phase 3: Initiating service shutdown procedures"

    # Critical services to shut down
    SERVICES=("apache2" "nginx" "mysql" "postgresql" "ssh" "postfix" "dovecot")

    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log "Stopping service: $service"
            sudo systemctl stop "$service"
        fi
    done

    # Kill suspicious processes
    log "Terminating suspicious processes..."
    sudo pkill -9 -f "suspicious\|malware\|unknown" || true

    # Disable SSH password authentication
    if [ -f /etc/ssh/sshd_config ]; then
        sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        sudo systemctl reload ssh 2>/dev/null || true
    fi

    log "Service shutdown completed"
}

# Phase 4: Containment Verification
verify_containment() {
    log "Phase 4: Verifying containment effectiveness"

    # Check VM isolation
    if [ -n "$VM_NAME" ]; then
        info "VM Status:"
        VBoxManage showvminfo "$VM_NAME" | grep -E "(State|NIC)" | head -5
    fi

    # Check network blocking
    info "Firewall Status:"
    sudo iptables -L CONTAINMENT 2>/dev/null | head -10 || echo "No containment chain found"

    # Check service status
    info "Service Status:"
    for service in apache2 mysql ssh; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            warning "Service still running: $service"
        else
            log "Service stopped: $service"
        fi
    done

    log "Containment verification completed"
}

# Phase 5: Evidence Preservation
preserve_evidence() {
    log "Phase 5: Preserving evidence during containment"

    # Create evidence directory
    EVIDENCE_DIR="/evidence/containment_$CASE_NUMBER"
    mkdir -p "$EVIDENCE_DIR"

    # Collect system state
    uname -a > "$EVIDENCE_DIR/system_info.txt"
    ps aux > "$EVIDENCE_DIR/process_list.txt"
    netstat -tuln > "$EVIDENCE_DIR/network_connections.txt"
    iptables -L -n > "$EVIDENCE_DIR/firewall_rules.txt"

    # Collect logs
    cp -r /var/log "$EVIDENCE_DIR/" 2>/dev/null || true

    # Generate integrity hashes
    find "$EVIDENCE_DIR" -type f -exec sha256sum {} \; > "$EVIDENCE_DIR/integrity_hashes.sha256"

    log "Evidence preserved in: $EVIDENCE_DIR"
}

# Main execution
main() {
    log "Starting Automated Containment Playbook"
    log "Case Number: $CASE_NUMBER"
    log "Target VM: $VM_NAME"

    # Execute containment phases
    isolate_host
    block_network_traffic
    shutdown_services
    verify_containment
    preserve_evidence

    log "Containment playbook execution completed"
    info "Containment log and evidence preserved"
    info "Next steps: Perform forensic analysis and eradication"
}

# Show usage if no arguments
if [ $# -eq 0 ]; then
    echo "Automated Containment Playbook for Incident Response"
    echo "=================================================="
    echo ""
    echo "Usage:"
    echo "  $0 <vm_name> [case_number]"
    echo ""
    echo "Arguments:"
    echo "  vm_name      Name of the VirtualBox VM to contain"
    echo "  case_number  Unique case identifier (auto-generated if not provided)"
    echo ""
    echo "Examples:"
    echo "  $0 'Parrot OS IR' INCIDENT_001"
    echo "  $0 'Compromised-VM'"
    echo ""
    echo "This script performs:"
    echo "  1. VM host isolation in VirtualBox"
    echo "  2. Network traffic blocking"
    echo "  3. Service shutdown procedures"
    echo "  4. Containment verification"
    echo "  5. Evidence preservation"
    echo ""
    exit 0
fi

# Run main function
main "$@"
EOF

sudo chmod +x /usr/local/bin/containment_playbook.sh
```

### Containment Success Metrics

- **Isolation Time**: < 5 minutes from detection to full isolation
- **Network Blocking Effectiveness**: 100% blocking of malicious traffic
- **Service Shutdown Completeness**: All non-essential services stopped
- **Evidence Preservation**: All containment actions logged and hashed
- **Recovery Time**: < 30 minutes to restore normal operations

### Lessons Learned and Improvements

- Regular containment playbook testing
- Automated alerting integration
- Backup power-off procedures for uncooperative VMs
- Integration with SIEM for automated containment triggers

Remember: These playbooks are living documents that should be updated regularly based on lessons learned and evolving threats.