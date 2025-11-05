# Parrot OS Incident Response Tools and Procedures Guide

## Document Information

| Document ID | Version | Effective Date | Review Date | Approved By |
|-------------|---------|----------------|-------------|-------------|
| PROC-PARROT-IR-001 | 1.0 | 2024-11-03 | 2025-11-03 | Chief Information Security Officer |

## Overview

This comprehensive guide documents all incident response (IR) tools and procedures available in Parrot OS for the GRC Portal environment. Parrot OS serves as the primary IR platform, providing specialized tools for digital forensics, network analysis, memory forensics, and evidence collection.

## Core IR Tools in Parrot OS

### 1. Wazuh SIEM Integration

#### Installation and Configuration
```bash
# Install Wazuh agent on Parrot OS
sudo apt update
sudo apt install -y curl apt-transport-https lsb-release gnupg2

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Install and configure agent
sudo apt update
sudo apt install -y wazuh-agent
sudo /var/ossec/bin/manage_agents  # Interactive registration

# Start agent
sudo systemctl start wazuh-agent
sudo systemctl enable wazuh-agent
```

#### Key Commands
```bash
# Check agent status
sudo systemctl status wazuh-agent

# View agent logs
sudo tail -f /var/ossec/logs/ossec.log

# Test agent connectivity
sudo /var/ossec/bin/agent_control -l

# Restart agent
sudo systemctl restart wazuh-agent
```

#### Custom Rules Configuration
```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->
<group name="custom_rules">
  <!-- Rule 1: Failed SSH Authentication -->
  <rule id="100001" level="10">
    <if_sid>5710</if_sid>
    <match>Failed password</match>
    <description>Failed SSH authentication attempt</description>
  </rule>

  <!-- Rule 2: Suspicious File Access -->
  <rule id="100002" level="12">
    <if_sid>550</if_sid>
    <match>access|read|write</match>
    <description>Suspicious file access detected</description>
  </rule>

  <!-- Rule 3: Network Anomaly -->
  <rule id="100003" level="8">
    <if_sid>530</if_sid>
    <match>connection refused|timeout</match>
    <description>Network connection anomaly detected</description>
  </rule>
</group>
```

### 2. Wireshark Network Analysis

#### Installation
```bash
# Install Wireshark and related tools
sudo apt update
sudo apt install -y wireshark wireshark-common tshark tcpdump ngrep

# Add user to wireshark group
sudo usermod -a -G wireshark $USER
```

#### Capture Filters for IR
```bash
# SSH traffic monitoring
tshark -i eth0 -f "tcp port 22" -w ssh_traffic.pcap

# HTTP/HTTPS traffic
tshark -i eth0 -f "tcp port 80 or tcp port 443" -w web_traffic.pcap

# Suspicious ports
tshark -i eth0 -f "tcp port 3389 or tcp port 5900 or tcp port 4444" -w suspicious_ports.pcap

# SYN scan detection
tshark -i eth0 -f "tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0" -w syn_scans.pcap

# Large packets (potential exfiltration)
tshark -i eth0 -f "frame.len > 1500" -w large_packets.pcap
```

#### Analysis Commands
```bash
# Display capture summary
tshark -r capture.pcap -q -z io,stat,1

# Extract HTTP requests
tshark -r capture.pcap -T fields -e http.request.method -e http.request.uri

# Find suspicious IPs
tshark -r capture.pcap -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -nr

# Extract DNS queries
tshark -r capture.pcap -T fields -e dns.qry.name -e dns.a
```

### 3. Volatility Memory Forensics

#### Installation
```bash
# Install Volatility
sudo apt update
sudo apt install -y volatility volatility-tools python3-volatility

# Clone latest version (optional)
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
sudo python3 setup.py install
```

#### Memory Acquisition
```bash
# Install LiME for live memory acquisition
sudo apt install -y lime-forensics

# Load LiME kernel module
sudo insmod /usr/lib/modules/$(uname -r)/kernel/drivers/misc/lime.ko \
"path=/evidence/memory_dump.lime format=lime"

# Alternative: Use /dev/mem (if available)
sudo dd if=/dev/mem of=/evidence/memory_dump.raw bs=1M count=1024
```

#### Memory Analysis Commands
```bash
# Detect profile
vol.py -f memory_dump.lime linux.info

# List running processes
vol.py -f memory_dump.lime linux.pslist

# Check network connections
vol.py -f memory_dump.lime linux.netstat

# Extract command line arguments
vol.py -f memory_dump.lime linux.cmdline

# Dump suspicious process memory
vol.py -f memory_dump.lime linux.dump.Dump -p <PID> -O /evidence/process_dump.dmp

# Analyze DLLs (Windows) or shared libraries (Linux)
vol.py -f memory_dump.lime linux.library_list

# Check for rootkits
vol.py -f memory_dump.lime linux.check_modules
```

### 4. Disk Imaging and Analysis

#### Forensic Imaging Tools
```bash
# Install The Sleuth Kit and autopsy
sudo apt install -y sleuthkit autopsy dc3dd

# Create forensic disk image
sudo dc3dd if=/dev/sda of=/evidence/disk_image.dd hash=sha256 log=/evidence/imaging.log

# Verify image integrity
sha256sum /evidence/disk_image.dd
```

#### File System Analysis
```bash
# Analyze file system structure
fls -r /evidence/disk_image.dd > /evidence/file_structure.txt

# Extract file metadata (MAC times)
mactime -b /evidence/file_structure.txt > /evidence/timeline.csv

# Find deleted files
fls -d /evidence/disk_image.dd > /evidence/deleted_files.txt

# Extract file content from unallocated space
blkcat /evidence/disk_image.dd <inode> > /evidence/unallocated_data.bin
```

### 5. Network Isolation Tools

#### VirtualBox Network Management
```bash
# Power off VM immediately
VBoxManage controlvm "Compromised-VM" acpipowerbutton

# Disconnect network interfaces
VBoxManage modifyvm "Compromised-VM" --nic1 null
VBoxManage modifyvm "Compromised-VM" --nic2 null

# Create containment snapshot
VBoxManage snapshot "Compromised-VM" take "CONTAINMENT_SNAPSHOT" --description "Network isolated"
```

#### Firewall and Network Controls
```bash
# UFW (Uncomplicated Firewall)
sudo ufw enable
sudo ufw deny from 192.168.1.100  # Block specific IP
sudo ufw deny 3389/tcp            # Block RDP
sudo ufw deny 5900/tcp            # Block VNC
sudo ufw reload

# Advanced iptables rules
sudo iptables -I INPUT -s 192.168.1.100 -j DROP
sudo iptables -I OUTPUT -d 192.168.1.100 -j DROP
sudo iptables -I FORWARD -s 192.168.1.100 -j DROP

# Make rules persistent
sudo apt install -y iptables-persistent
```

#### Network Namespace Isolation
```bash
# Create quarantine namespace
sudo ip netns add quarantine

# Create virtual ethernet pair
sudo ip link add veth-quar host type veth peer name veth-quar netns quarantine

# Configure quarantine network
sudo ip netns exec quarantine ip link set lo up
sudo ip netns exec quarantine ip link set veth-quar up
sudo ip netns exec quarantine ip addr add 192.168.201.2/24 dev veth-quar
```

### 6. Log Analysis Tools

#### System Log Analysis
```bash
# Enhanced syslog configuration
sudo tee /etc/rsyslog.d/50-wazuh.conf << EOF
*.* @@wazuh-manager-ip:514
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
EOF

# Analyze authentication logs
grep "Failed password" /var/log/auth.log | head -20

# Monitor system logs in real-time
tail -f /var/log/syslog | grep -i "error\|warning\|critical"
```

#### Log Correlation
```bash
# Use log analysis tools
sudo apt install -y rsyslog logwatch

# Correlate logs with time windows
awk '$1 >= "2024-11-03 14:00" && $1 <= "2024-11-03 16:00"' /var/log/auth.log

# Search for patterns across multiple logs
grep -r "192.168.1.100" /var/log/
```

### 7. Evidence Collection Automation

#### Automated Evidence Collection Script
```bash
#!/bin/bash
# Automated Evidence Collection Script

CASE_NUMBER=$1
EVIDENCE_DIR="/evidence/case_$CASE_NUMBER"

# Create evidence structure
mkdir -p "$EVIDENCE_DIR"/{disk_images,memory_dumps,network_captures,file_artifacts,logs}

# Collect system information
uname -a > "$EVIDENCE_DIR/system_info.txt"
ps aux > "$EVIDENCE_DIR/processes.txt"
netstat -tuln > "$EVIDENCE_DIR/network_connections.txt"

# Collect file artifacts
cp ~/.bash_history "$EVIDENCE_DIR/"
cp -r ~/.ssh "$EVIDENCE_DIR/" 2>/dev/null

# Generate integrity hashes
find "$EVIDENCE_DIR" -type f -exec sha256sum {} \; > "$EVIDENCE_DIR/integrity_hashes.sha256"

echo "Evidence collection completed for case $CASE_NUMBER"
```

#### Forensic Imaging Script
```bash
#!/bin/bash
# Forensic Disk Imaging Script

SOURCE_DEVICE=$1
OUTPUT_FILE=$2
CASE_NUMBER=$3

EVIDENCE_DIR="/evidence/case_$CASE_NUMBER/disk_images"

# Create forensic image with verification
dc3dd if="$SOURCE_DEVICE" of="$EVIDENCE_DIR/$OUTPUT_FILE" \
      hash=sha256 log="$EVIDENCE_DIR/imaging.log"

# Generate hash verification
sha256sum "$EVIDENCE_DIR/$OUTPUT_FILE" > "$EVIDENCE_DIR/$OUTPUT_FILE.sha256"

echo "Forensic imaging completed"
```

## IR Procedures in Parrot OS

### 1. Initial Incident Triage
```bash
# Quick system assessment
uname -a
uptime
df -h
free -h
ps aux | head -20
netstat -tuln | head -20

# Check for suspicious activity
ps aux | grep -i "suspicious\|malware\|unknown"
netstat -tuln | grep -E "(4444|6667|6668)"  # Common C2 ports
find /tmp -name "*" -type f -mtime -1 2>/dev/null
```

### 2. Memory Analysis Procedure
```bash
# Step 1: Acquire memory
sudo insmod lime.ko "path=/evidence/memory.lime format=lime"

# Step 2: Profile detection
vol.py -f /evidence/memory.lime linux.info

# Step 3: Process analysis
vol.py -f /evidence/memory.lime linux.pslist > processes.txt
vol.py -f /evidence/memory.lime linux.netstat > network.txt

# Step 4: Suspicious process investigation
vol.py -f /evidence/memory.lime linux.cmdline | grep -i "suspicious"
```

### 3. Network Traffic Analysis
```bash
# Step 1: Start capture
tshark -i eth0 -w incident_traffic.pcap -b duration:3600 -b files:5

# Step 2: Real-time analysis
tshark -i eth0 -f "tcp port 22" -T fields -e ip.src -e ip.dst

# Step 3: Extract suspicious connections
tshark -r incident_traffic.pcap -T fields -e ip.src | sort | uniq -c | sort -nr | head -10
```

### 4. File System Forensics
```bash
# Step 1: Create disk image
dc3dd if=/dev/sda of=/evidence/disk.dd hash=sha256

# Step 2: Analyze file system
fls -r /evidence/disk.dd > file_structure.txt

# Step 3: Timeline analysis
mactime -b file_structure.txt > timeline.csv

# Step 4: Extract deleted files
fls -d /evidence/disk.dd > deleted_files.txt
```

### 5. Log Correlation and Analysis
```bash
# Step 1: Collect all relevant logs
cp /var/log/auth.log /evidence/
cp /var/log/syslog /evidence/
cp /var/log/wazuh/alerts.log /evidence/

# Step 2: Time-based correlation
for log in /evidence/*.log; do
    echo "=== $log ==="
    awk '/2024-11-03 14:00/,/2024-11-03 16:00/' "$log" | head -10
done

# Step 3: Pattern analysis
grep -r "192.168.1.100" /evidence/
```

## Tool Integration and Automation

### Automated IR Response Script
```bash
#!/bin/bash
# Comprehensive IR Automation Script

INCIDENT_ID=$1
TARGET_VM=$2

echo "Starting automated IR response for incident $INCIDENT_ID"

# Phase 1: Containment
VBoxManage controlvm "$TARGET_VM" acpipowerbutton
VBoxManage modifyvm "$TARGET_VM" --nic1 null
VBoxManage snapshot "$TARGET_VM" take "IR_CONTAINMENT_$INCIDENT_ID"

# Phase 2: Evidence Collection
./collect_evidence.sh "$INCIDENT_ID"

# Phase 3: Network Isolation
iptables -I INPUT -s malicious_ip -j DROP
ufw deny from malicious_ip

# Phase 4: Memory Analysis
vol.py -f /evidence/memory.lime linux.pslist > /evidence/processes.txt

echo "Automated IR response completed"
```

### Continuous Monitoring Setup
```bash
# Install monitoring tools
sudo apt install -y htop iotop nmon sysstat

# Configure system monitoring
sudo tee /etc/cron.d/system_monitor << EOF
*/5 * * * * root /usr/local/bin/system_health_check.sh
0 * * * * root /usr/local/bin/log_analysis.sh
EOF

# Real-time monitoring
watch -n 5 'ps aux | head -10; echo "---"; netstat -tuln | wc -l'
```

## Performance Benchmarks

### Tool Performance Metrics
- **Wazuh Agent**: < 50MB RAM, < 5% CPU during normal operation
- **Wireshark Capture**: < 1000 packets/second processing
- **Volatility Analysis**: < 5 minutes for 4GB memory image
- **Disk Imaging**: < 30 minutes for 500GB disk (USB 3.0)
- **Log Analysis**: < 10 seconds for 1GB log file

### System Requirements
- **RAM**: Minimum 4GB, Recommended 8GB+
- **Storage**: 100GB+ for evidence storage
- **CPU**: Multi-core processor for parallel analysis
- **Network**: Gigabit Ethernet for traffic capture

## Security Considerations

### Tool Security
- Run forensic tools as non-privileged user when possible
- Use read-only mounts for evidence disks
- Implement proper chain of custody procedures
- Encrypt evidence storage and transmission

### Operational Security
- Isolate IR environment from production networks
- Use VPN for remote access to IR systems
- Implement multi-factor authentication
- Regular security updates for all IR tools

## Training and Certification

### Required Skills
- Linux system administration
- Network protocol analysis
- Memory and disk forensics
- Incident response procedures
- Tool-specific command line usage

### Recommended Certifications
- GIAC Certified Forensic Analyst (GCFA)
- GIAC Certified Incident Handler (GCIH)
- Certified Ethical Hacker (CEH)
- CompTIA Security+

## Maintenance and Updates

### Tool Updates
```bash
# Update all IR tools
sudo apt update
sudo apt upgrade -y

# Update Volatility
cd volatility3
git pull
sudo python3 setup.py install

# Update Wazuh
sudo apt install --only-upgrade wazuh-agent
```

### Configuration Backups
```bash
# Backup tool configurations
tar -czf /backups/ir_tools_config_$(date +%Y%m%d).tar.gz \
    /var/ossec/etc/ \
    /etc/wireshark/ \
    ~/.volatilityrc \
    /etc/rsyslog.d/
```

## Troubleshooting

### Common Issues and Solutions

#### Wazuh Agent Connection Issues
```bash
# Check agent status
sudo systemctl status wazuh-agent

# Check connectivity
telnet wazuh-manager 1514

# Restart agent
sudo systemctl restart wazuh-agent

# Check logs
sudo tail -50 /var/ossec/logs/ossec.log
```

#### Wireshark Permission Issues
```bash
# Add user to wireshark group
sudo usermod -a -G wireshark $USER

# Restart session or use sudo
sudo wireshark
```

#### Volatility Profile Issues
```bash
# List available profiles
vol.py --info | grep Profile

# Manual profile specification
vol.py -f memory.dmp --profile=Win7SP1x64
```

## Appendices

### Appendix A: Tool Command Reference
Complete command reference for all IR tools

### Appendix B: Script Library
Collection of automated IR scripts

### Appendix C: Performance Tuning
Optimization settings for IR tools

### Appendix D: Integration APIs
APIs for tool integration with GRC Portal

---

**Document Control:**
- **Created By:** Security Team
- **Approved By:** CISO
- **Review Cycle:** Annual
- **Last Updated:** 2024-11-03