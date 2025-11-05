# Recovery Validation Checklist

## Document Information

| Document ID | Version | Effective Date | Review Date | Approved By |
|-------------|---------|----------------|-------------|-------------|
| PROC-RECOVERY-VALIDATION-001 | 1.0 | 2024-11-03 | 2025-11-03 | Chief Information Security Officer |

## Overview

This document provides comprehensive checklists for validating system recovery procedures in the GRC Portal environment. It covers VirtualBox environment restoration, Parrot OS system recovery, and network configuration recovery validation through systematic testing procedures.

## Recovery Validation Framework

### Validation Objectives
- Ensure complete system restoration
- Verify functionality of recovered systems
- Validate security controls integrity
- Confirm operational readiness
- Document validation results

### Validation Phases
1. **Pre-Recovery Validation**: Baseline assessment
2. **Recovery Execution**: Step-by-step validation
3. **Post-Recovery Testing**: Comprehensive verification
4. **Operational Validation**: Production readiness assessment

## VirtualBox Environment Validation

### VM Recovery Validation Checklist

#### Pre-Recovery Assessment
- [ ] Backup integrity verified (SHA256 hashes match)
- [ ] VM configuration documented
- [ ] Network settings recorded
- [ ] Snapshot history reviewed
- [ ] Storage space availability confirmed
- [ ] Host system resources adequate

#### VM Creation and Configuration Validation
- [ ] VM created successfully in VirtualBox
- [ ] VM name matches recovery requirements
- [ ] OS type configured correctly
- [ ] Memory allocation appropriate
- [ ] CPU allocation sufficient
- [ ] Storage configuration correct
- [ ] Network adapters configured
- [ ] Shared folders mounted (if applicable)

#### Boot and OS Validation
- [ ] VM boots without errors
- [ ] OS loads completely
- [ ] Login credentials work
- [ ] System time synchronized
- [ ] Network connectivity established
- [ ] Basic system commands functional
- [ ] System logs accessible

#### Application and Service Validation
- [ ] Core applications installed
- [ ] Services start automatically
- [ ] Configuration files restored
- [ ] User data accessible
- [ ] Permissions correct
- [ ] Scheduled tasks operational

### VirtualBox Network Validation

#### Network Adapter Configuration
- [ ] Network adapter type correct (NAT/Bridged/Host-only)
- [ ] IP address assigned correctly
- [ ] Subnet mask configured properly
- [ ] Default gateway reachable
- [ ] DNS servers configured
- [ ] Network interface active

#### Connectivity Testing
- [ ] Local network connectivity verified
- [ ] Internet access functional
- [ ] Host-guest communication working
- [ ] Inter-VM communication established
- [ ] Firewall rules applied correctly

#### Advanced Networking Validation
- [ ] VLAN configuration correct (if applicable)
- [ ] VPN connections established
- [ ] Port forwarding configured
- [ ] Network isolation maintained
- [ ] Traffic filtering operational

### VirtualBox Integration Testing

#### Host Integration
- [ ] Shared folders accessible
- [ ] USB device passthrough working
- [ ] Clipboard sharing functional
- [ ] Drag-and-drop operational
- [ ] Seamless mode available

#### Snapshot and Backup Validation
- [ ] Snapshots created successfully
- [ ] Snapshot restoration functional
- [ ] Backup procedures documented
- [ ] Recovery time objectives met

## Parrot OS System Validation

### OS Installation Validation

#### Base System Validation
- [ ] OS version correct (Parrot OS)
- [ ] Kernel version appropriate
- [ ] System architecture matches hardware
- [ ] Boot loader configured correctly
- [ ] GRUB menu accessible
- [ ] Emergency boot options available

#### Package and Repository Validation
- [ ] Package manager functional (apt)
- [ ] Repository sources configured
- [ ] Package database updated
- [ ] Core packages installed
- [ ] Package integrity verified

#### User and Permission Validation
- [ ] Root account configured
- [ ] IR user account created
- [ ] Sudo privileges assigned
- [ ] User home directories created
- [ ] File permissions correct
- [ ] SSH keys configured (if applicable)

### IR Tools Validation

#### Forensic Tools Validation
- [ ] Volatility installed and functional
- [ ] The Sleuth Kit (TSK) operational
- [ ] Wireshark/tshark working
- [ ] tcpdump capturing traffic
- [ ] Autopsy forensic browser functional
- [ ] dc3dd imaging tool available

#### Memory Analysis Tools
- [ ] LiME kernel module available
- [ ] Memory acquisition possible
- [ ] Volatility profiles loaded
- [ ] Memory analysis commands functional

#### Network Analysis Tools
- [ ] Wireshark dissectors working
- [ ] Network capture interfaces available
- [ ] Protocol analysis functional
- [ ] Packet filtering operational

#### Disk Forensics Tools
- [ ] Disk imaging tools functional
- [ ] File system analysis working
- [ ] Timeline creation possible
- [ ] Deleted file recovery operational

### Security Configuration Validation

#### SSH Configuration
- [ ] SSH service running
- [ ] Port configuration correct
- [ ] Authentication methods configured
- [ ] Access restrictions applied
- [ ] Logging enabled

#### Firewall Configuration
- [ ] UFW/iptables active
- [ ] Default policies correct
- [ ] Required ports open
- [ ] Unnecessary ports closed
- [ ] Rules logged appropriately

#### System Hardening
- [ ] Password policies enforced
- [ ] Account lockout configured
- [ ] Audit logging enabled
- [ ] File integrity monitoring active
- [ ] Automatic updates configured

## Network Configuration Validation

### Infrastructure Validation

#### Router/Switch Configuration
- [ ] Device configurations loaded
- [ ] Interface configurations correct
- [ ] Routing tables populated
- [ ] Access control lists applied
- [ ] VLAN configurations correct
- [ ] Port security enabled

#### Network Service Validation
- [ ] DHCP server operational
- [ ] DNS resolution working
- [ ] NTP synchronization active
- [ ] Network monitoring functional
- [ ] Log aggregation working

### Security Controls Validation

#### Firewall and IDS/IPS
- [ ] Firewall rules active
- [ ] IDS signatures updated
- [ ] IPS blocking functional
- [ ] Alert generation working
- [ ] False positive rate acceptable

#### VPN and Remote Access
- [ ] VPN server operational
- [ ] Authentication working
- [ ] Encryption configured
- [ ] Access controls enforced
- [ ] Logging enabled

#### Network Segmentation
- [ ] Network zones defined
- [ ] Traffic filtering operational
- [ ] Access controls working
- [ ] Isolation maintained
- [ ] Monitoring coverage complete

## Functional Testing Procedures

### Basic Functionality Testing

#### System Commands Testing
```bash
# Test basic system functionality
uname -a                    # System information
df -h                       # Disk space
free -h                     # Memory usage
ps aux | head -10          # Process list
netstat -tuln | head -10    # Network connections
systemctl list-units --type=service --state=running | head -10  # Services
```

#### Network Testing
```bash
# Test network connectivity
ping -c 4 8.8.8.8         # Internet connectivity
ping -c 4 localhost        # Local connectivity
nslookup google.com        # DNS resolution
curl -I https://www.google.com  # HTTPS connectivity
ssh -T git@github.com      # SSH connectivity
```

#### IR Tools Testing
```bash
# Test forensic tools
vol.py --info | head -5    # Volatility
wireshark --version        # Wireshark
tcpdump --version          # tcpdump
fls -V                     # TSK tools
```

### Advanced Testing Procedures

#### Memory Forensics Testing
```bash
#!/bin/bash
# Memory Forensics Validation Script

echo "Testing memory forensics capabilities..."

# Test LiME module loading
if sudo modprobe lime "path=/tmp/test_memory.lime format=lime" 2>/dev/null; then
    echo "✓ LiME kernel module loads successfully"
    sudo rmmod lime 2>/dev/null
else
    echo "✗ LiME kernel module failed to load"
fi

# Test Volatility basic functionality
if vol.py --info >/dev/null 2>&1; then
    echo "✓ Volatility framework operational"
else
    echo "✗ Volatility framework not working"
fi

# Test memory profile detection
if [ -f /tmp/test_memory.lime ]; then
    if vol.py -f /tmp/test_memory.lime linux.info >/dev/null 2>&1; then
        echo "✓ Memory profile detection working"
    else
        echo "✗ Memory profile detection failed"
    fi
    rm -f /tmp/test_memory.lime
fi

echo "Memory forensics testing completed"
```

#### Network Analysis Testing
```bash
#!/bin/bash
# Network Analysis Validation Script

echo "Testing network analysis capabilities..."

# Test packet capture
if timeout 5 tcpdump -i lo -c 1 >/dev/null 2>&1; then
    echo "✓ Packet capture functional"
else
    echo "✗ Packet capture not working"
fi

# Test Wireshark/tshark
if tshark --version >/dev/null 2>&1; then
    echo "✓ Wireshark/tshark operational"
else
    echo "✗ Wireshark/tshark not functional"
fi

# Test network interface detection
if tshark -D | grep -q "lo\|eth0\|enp"; then
    echo "✓ Network interfaces detected"
else
    echo "✗ Network interfaces not found"
fi

echo "Network analysis testing completed"
```

#### Disk Forensics Testing
```bash
#!/bin/bash
# Disk Forensics Validation Script

echo "Testing disk forensics capabilities..."

# Test disk imaging
if dc3dd --version >/dev/null 2>&1; then
    echo "✓ Disk imaging tool available"
else
    echo "✗ Disk imaging tool not found"
fi

# Test file system analysis
if fls -V >/dev/null 2>&1; then
    echo "✓ File system analysis tools operational"
else
    echo "✗ File system analysis tools not working"
fi

# Test timeline creation
if mactime -V >/dev/null 2>&1; then
    echo "✓ Timeline analysis tools available"
else
    echo "✗ Timeline analysis tools not found"
fi

echo "Disk forensics testing completed"
```

### Integration Testing

#### VirtualBox-Parrot OS Integration
- [ ] VM starts from VirtualBox interface
- [ ] Parrot OS boots successfully
- [ ] Network connectivity between host and guest
- [ ] Shared folders accessible
- [ ] IR tools functional within VM
- [ ] Evidence transfer possible

#### Multi-Component Testing
- [ ] Wazuh agent communication with manager
- [ ] SIEM correlation rules functional
- [ ] Automated alerting operational
- [ ] Incident response workflows tested
- [ ] Backup and recovery procedures validated

## Automated Validation Scripts

### Comprehensive Validation Suite
```bash
#!/bin/bash
# Comprehensive Recovery Validation Script

VALIDATION_LOG="/var/log/recovery_validation_$(date +%Y%m%d_%H%M%S).log"
ISSUES_FOUND=0

echo "Starting comprehensive recovery validation..." | tee -a "$VALIDATION_LOG"
echo "Validation started: $(date)" | tee -a "$VALIDATION_LOG"

# Function to log results
log_result() {
    local test_name="$1"
    local result="$2"
    local details="$3"

    if [ "$result" = "PASS" ]; then
        echo "✓ $test_name: PASS" | tee -a "$VALIDATION_LOG"
    else
        echo "✗ $test_name: FAIL - $details" | tee -a "$VALIDATION_LOG"
        ((ISSUES_FOUND++))
    fi
}

# VirtualBox validation
validate_virtualbox() {
    echo "Validating VirtualBox environment..." | tee -a "$VALIDATION_LOG"

    # Check VirtualBox installation
    if command -v VBoxManage >/dev/null 2>&1; then
        log_result "VirtualBox Installation" "PASS"
    else
        log_result "VirtualBox Installation" "FAIL" "VBoxManage not found"
        return
    fi

    # Check VM existence
    if VBoxManage list vms | grep -q "Parrot-OS-IR"; then
        log_result "VM Existence" "PASS"
    else
        log_result "VM Existence" "FAIL" "Parrot-OS-IR VM not found"
    fi

    # Check VM state
    vm_state=$(VBoxManage showvminfo "Parrot-OS-IR" --machinereadable 2>/dev/null | grep VMState= | cut -d'"' -f2)
    if [ "$vm_state" = "poweroff" ] || [ "$vm_state" = "saved" ]; then
        log_result "VM State" "PASS"
    else
        log_result "VM State" "FAIL" "VM state: $vm_state"
    fi
}

# Parrot OS validation
validate_parrot_os() {
    echo "Validating Parrot OS system..." | tee -a "$VALIDATION_LOG"

    # This would run inside the VM
    # For now, check if we can detect Parrot OS environment
    if [ -f /etc/os-release ] && grep -q "Parrot" /etc/os-release; then
        log_result "OS Detection" "PASS"
    else
        log_result "OS Detection" "FAIL" "Not running Parrot OS"
    fi

    # Check kernel version
    kernel_version=$(uname -r)
    if [[ $kernel_version == *"parrot"* ]] || [[ $kernel_version == *"amd64"* ]]; then
        log_result "Kernel Version" "PASS"
    else
        log_result "Kernel Version" "FAIL" "Kernel: $kernel_version"
    fi
}

# Network validation
validate_network() {
    echo "Validating network configuration..." | tee -a "$VALIDATION_LOG"

    # Check network interfaces
    if ip link show | grep -q "state UP"; then
        log_result "Network Interfaces" "PASS"
    else
        log_result "Network Interfaces" "FAIL" "No active network interfaces"
    fi

    # Check internet connectivity
    if ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        log_result "Internet Connectivity" "PASS"
    else
        log_result "Internet Connectivity" "FAIL" "Cannot reach internet"
    fi

    # Check DNS resolution
    if nslookup google.com >/dev/null 2>&1; then
        log_result "DNS Resolution" "PASS"
    else
        log_result "DNS Resolution" "FAIL" "DNS resolution failed"
    fi
}

# IR tools validation
validate_ir_tools() {
    echo "Validating IR tools..." | tee -a "$VALIDATION_LOG"

    # Check Volatility
    if command -v vol.py >/dev/null 2>&1; then
        log_result "Volatility" "PASS"
    else
        log_result "Volatility" "FAIL" "vol.py not found"
    fi

    # Check Wireshark
    if command -v tshark >/dev/null 2>&1; then
        log_result "Wireshark" "PASS"
    else
        log_result "Wireshark" "FAIL" "tshark not found"
    fi

    # Check TSK tools
    if command -v fls >/dev/null 2>&1; then
        log_result "TSK Tools" "PASS"
    else
        log_result "TSK Tools" "FAIL" "fls not found"
    fi

    # Check Wazuh agent
    if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
        log_result "Wazuh Agent" "PASS"
    else
        log_result "Wazuh Agent" "FAIL" "Wazuh agent not running"
    fi
}

# Security validation
validate_security() {
    echo "Validating security configuration..." | tee -a "$VALIDATION_LOG"

    # Check SSH configuration
    if [ -f /etc/ssh/sshd_config ]; then
        if grep -q "PasswordAuthentication no" /etc/ssh/sshd_config; then
            log_result "SSH Password Auth" "PASS"
        else
            log_result "SSH Password Auth" "FAIL" "Password authentication enabled"
        fi
    fi

    # Check firewall
    if sudo ufw status | grep -q "Status: active"; then
        log_result "Firewall Status" "PASS"
    else
        log_result "Firewall Status" "FAIL" "Firewall not active"
    fi

    # Check sudo configuration
    if [ -f /etc/sudoers ] && grep -q "%wheel ALL=(ALL) ALL" /etc/sudoers; then
        log_result "Sudo Configuration" "PASS"
    else
        log_result "Sudo Configuration" "FAIL" "Sudo not properly configured"
    fi
}

# Run all validations
validate_virtualbox
validate_parrot_os
validate_network
validate_ir_tools
validate_security

# Summary
echo "" | tee -a "$VALIDATION_LOG"
echo "VALIDATION SUMMARY" | tee -a "$VALIDATION_LOG"
echo "=================" | tee -a "$VALIDATION_LOG"
if [ "$ISSUES_FOUND" -eq 0 ]; then
    echo "✓ All validation checks passed!" | tee -a "$VALIDATION_LOG"
    exit 0
else
    echo "✗ $ISSUES_FOUND validation issues found" | tee -a "$VALIDATION_LOG"
    echo "Check $VALIDATION_LOG for details" | tee -a "$VALIDATION_LOG"
    exit 1
fi
```

### Validation Report Generation
```bash
#!/bin/bash
# Validation Report Generator

VALIDATION_LOG="$1"
REPORT_FILE="/evidence/validation_report_$(date +%Y%m%d_%H%M%S).md"

if [ ! -f "$VALIDATION_LOG" ]; then
    echo "Validation log not found: $VALIDATION_LOG"
    exit 1
fi

# Count results
total_tests=$(grep -c "✓\|✗" "$VALIDATION_LOG")
passed_tests=$(grep -c "✓" "$VALIDATION_LOG")
failed_tests=$(grep -c "✗" "$VALIDATION_LOG")

# Generate report
cat > "$REPORT_FILE" << EOF
# Recovery Validation Report

## Executive Summary
- **Validation Date**: $(date)
- **Total Tests**: $total_tests
- **Passed Tests**: $passed_tests
- **Failed Tests**: $failed_tests
- **Success Rate**: $((passed_tests * 100 / total_tests))%

## Detailed Results

EOF

# Add detailed results
echo '### Passed Tests' >> "$REPORT_FILE"
grep "✓" "$VALIDATION_LOG" | sed 's/✓/- /' >> "$REPORT_FILE"

echo '' >> "$REPORT_FILE"
echo '### Failed Tests' >> "$REPORT_FILE"
grep "✗" "$VALIDATION_LOG" | sed 's/✗/- /' >> "$REPORT_FILE"

# Add recommendations
echo '' >> "$REPORT_FILE"
echo '## Recommendations' >> "$REPORT_FILE"
if [ "$failed_tests" -gt 0 ]; then
    echo 'Address the following failed tests before declaring recovery complete:' >> "$REPORT_FILE"
    grep "✗" "$VALIDATION_LOG" | sed 's/✗/- /' >> "$REPORT_FILE"
else
    echo 'All validation tests passed. Recovery is complete and validated.' >> "$REPORT_FILE"
fi

echo '' >> "$REPORT_FILE"
echo '## Next Steps' >> "$REPORT_FILE"
echo '1. Review validation results with recovery team' >> "$REPORT_FILE"
echo '2. Address any failed validation tests' >> "$REPORT_FILE"
echo '3. Update recovery procedures based on lessons learned' >> "$REPORT_FILE"
echo '4. Conduct post-recovery monitoring' >> "$REPORT_FILE"

echo "Validation report generated: $REPORT_FILE"
```

## Validation Metrics and KPIs

### Recovery Success Metrics
- **Validation Completion Rate**: Percentage of checklist items completed
- **Test Pass Rate**: Percentage of validation tests that pass
- **Recovery Time Achievement**: Meeting RTO/RPO objectives
- **System Availability**: Uptime following recovery
- **Functionality Verification**: All required features operational

### Quality Metrics
- **False Positive Rate**: Invalid validation failures
- **Automation Level**: Percentage of tests automated
- **Documentation Completeness**: All procedures documented
- **Team Satisfaction**: Recovery team feedback

### Performance Metrics
- **Validation Duration**: Time to complete all validation tests
- **Issue Resolution Time**: Time to fix validation failures
- **Resource Utilization**: System resources used during validation
- **Cost Effectiveness**: Cost per validation cycle

## Continuous Improvement

### Validation Process Review
- **Weekly Review**: Recent validation results and issues
- **Monthly Assessment**: Overall validation effectiveness
- **Quarterly Audit**: Validation process compliance
- **Annual Review**: Comprehensive process improvement

### Lessons Learned Integration
- **Process Updates**: Incorporate findings into procedures
- **Tool Improvements**: Enhance validation scripts and tools
- **Training Updates**: Update team training based on issues
- **Automation Enhancements**: Increase automated testing coverage

## Appendices

### Appendix A: Validation Checklists
- Complete checklist templates for each validation area
- Customization guidelines for different environments
- Scoring rubrics for validation results

### Appendix B: Testing Scripts
- Complete automated testing scripts
- Manual testing procedures
- Integration testing scenarios

### Appendix C: Validation Tools
- List of validation tools and their purposes
- Tool installation and configuration procedures
- Tool maintenance and update procedures

### Appendix D: Metrics and Reporting
- KPI definitions and calculation methods
- Reporting templates and schedules
- Dashboard configuration guidelines

---

**Document Control:**
- **Created By:** Security Team
- **Approved By:** CISO
- **Review Cycle:** Annual
- **Last Updated:** 2024-11-03