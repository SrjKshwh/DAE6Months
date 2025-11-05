# Sample Incident Report - Brute Force Authentication Attack

## Document Information

| Document ID | Version | Classification | Date Created | Incident ID |
|-------------|---------|----------------|--------------|-------------|
| IR-REP-SEC-001 | 1.0 | Confidential | 2024-11-03 | SEC-INC-001 |

## Executive Summary

**Incident Type:** Brute Force Authentication Attack

**Severity Level:** Critical

**Date/Time of Incident:** 2024-11-03 14:30 UTC - 2024-11-03 15:45 UTC

**Affected Systems:** Web Application Server (web-srv-01), Authentication Database (auth-db-01)

**Business Impact:** Potential unauthorized access to customer data; 15-minute service disruption during containment

**Current Status:** Closed - Eradicated and Recovered

## Incident Details

### Detection Information
- **Detection Date/Time:** 2024-11-03 15:42 UTC
- **Detection Method:** Automated Wazuh alert triggered by multiple failed authentication attempts
- **Initial Reporter:** Wazuh SIEM System
- **Detection Source:** Custom Wazuh rule ID 100001 (Failed SSH authentication)

### Incident Description
On November 3, 2024, at approximately 14:30 UTC, the Wazuh SIEM system detected multiple failed authentication attempts against the web application server (web-srv-01). The attack originated from IP address 192.168.1.100 and targeted administrative accounts. Over a 75-minute period, 47 failed login attempts were recorded, with the attacker attempting to brute-force the 'admin' account using common password patterns.

The attack was detected when the custom Wazuh rule triggered an alert after 5 failed attempts within a 10-minute window. Immediate containment procedures were initiated, isolating the affected server and blocking the attacking IP address.

### Affected Assets
| Asset Name | Asset Type | Criticality | Impact Level | Location |
|------------|------------|-------------|--------------|----------|
| web-srv-01 | Web Server | High | Severe | VirtualBox VM (Parrot OS) |
| auth-db-01 | Database | Critical | Moderate | Docker Container |
| api-gateway | Load Balancer | Medium | Minimal | AWS EC2 |

### Attack Vector Analysis
- **Primary Attack Vector:** Brute force authentication attack via SSH
- **Compromised Credentials:** No successful compromises detected
- **Malware Involved:** No malware detected
- **External IP Addresses:** 192.168.1.100 (attacking IP)
- **Command and Control:** None identified - direct attack

## Response Actions Taken

### Phase 1: Identification & Assessment
**Date/Time Started:** 2024-11-03 15:42 UTC
**Actions Taken:**
- Reviewed Wazuh alert details and log entries
- Queried authentication logs for attack pattern analysis
- Performed initial scope assessment - confirmed single IP source
- Collected preliminary evidence (log excerpts, timestamps)

**Personnel Involved:**
- Security Analyst (John Smith) - Alert triage and initial assessment
- Incident Response Lead (Jane Doe) - Response coordination

### Phase 2: Containment
**Date/Time Started:** 2024-11-03 15:45 UTC
**Short-term Containment:**
- Blocked attacking IP (192.168.1.100) in firewall
- Disabled SSH access temporarily on web-srv-01
- Isolated web-srv-01 from production network

**Long-term Containment:**
- Implemented account lockout policy (3 failed attempts)
- Enabled multi-factor authentication for admin accounts
- Updated firewall rules to restrict SSH access

**Tools Used:**
- VirtualBox: `VBoxManage modifyvm "web-srv-01" --nic1 null`
- Network Isolation: `iptables -I INPUT -s 192.168.1.100 -j DROP`
- Service Management: `systemctl stop ssh`

### Phase 3: Eradication
**Date/Time Started:** 2024-11-03 16:00 UTC
**Root Cause Identified:** Weak SSH configuration allowing unlimited authentication attempts

**Eradication Steps:**
- Patched SSH configuration with Fail2Ban integration
- Reset all potentially affected credentials
- Updated system with latest security patches
- Verified no backdoors or persistence mechanisms

**Tools Used:**
- Log Analysis: `grep "Failed password" /var/log/auth.log`
- Configuration Audit: `sshd -T | grep -E "(maxauthtries|permitemptypasswords)"`
- Vulnerability Scan: `nmap -p 22 --script ssh-auth-methods web-srv-01`

### Phase 4: Recovery
**Date/Time Started:** 2024-11-03 16:30 UTC
**System Recovery:**
- Restored SSH access with enhanced security controls
- Reconnected web-srv-01 to production network
- Validated system integrity and functionality
- Monitored for reoccurrence

**Validation Steps:**
- Successful SSH authentication test
- Application functionality verification
- Security control validation

### Phase 5: Lessons Learned
**Date/Time Completed:** 2024-11-03 17:00 UTC
**Effectiveness Assessment:**
- Detection worked well - automated alerting prevented successful breach
- Containment was effective - attack stopped within 3 minutes
- Could improve: Automated IP blocking response

**Preventive Measures:**
- Implemented Fail2Ban for automatic attack response
- Enhanced monitoring with geo-blocking
- Regular SSH configuration audits

## Evidence Collected

### Digital Evidence
| Evidence ID | Type | Description | Collection Method | Hash Value | Chain of Custody |
|-------------|------|-------------|-------------------|------------|------------------|
| EV-001 | Authentication Logs | SSH auth.log from attack period | `cp /var/log/auth.log /evidence/` | sha256: a1b2c3... | Collected by John Smith on 2024-11-03 15:45 UTC |
| EV-002 | Wazuh Alerts | SIEM alerts for failed auth attempts | Wazuh API export | sha256: d4e5f6... | Collected by Jane Doe on 2024-11-03 15:50 UTC |
| EV-003 | Network Capture | TCP traffic during attack | `tcpdump -i eth0 -w capture.pcap` | sha256: g7h8i9... | Collected by Security Team on 2024-11-03 16:00 UTC |

### Log Evidence
| Log Source | Time Range | Key Events | Location |
|------------|------------|------------|----------|
| Wazuh Agent | 14:30-15:45 UTC | 47 failed auth alerts | /var/log/wazuh/alerts.log |
| System Auth | 14:30-15:45 UTC | Failed password entries | /var/log/auth.log |
| Firewall | 15:45 UTC | IP block rule added | /var/log/ufw.log |

### Physical Evidence
- Screenshots of Wazuh dashboard showing attack in progress
- Printed network topology diagram with isolation points marked

## Impact Assessment

### Technical Impact
- **System Availability:** 15-minute downtime during containment
- **Data Integrity:** No data corruption or loss detected
- **System Performance:** Normal performance restored post-recovery

### Business Impact
- **Financial Loss:** $2,400 (15 minutes of service disruption at $160/minute)
- **Operational Disruption:** Web application temporarily unavailable
- **Customer Impact:** No customer data accessed; minimal user impact

### Compliance Impact
- **Regulatory Requirements:** No breach notification required (no successful access)
- **Notification Requirements:** Internal incident reporting completed
- **Audit Findings:** Will be documented in next security audit

## Root Cause Analysis

### Technical Root Cause
The incident occurred due to insufficient SSH hardening on web-srv-01. The server was configured with default SSH settings allowing unlimited authentication attempts without rate limiting or account lockout mechanisms.

### Contributing Factors
- Default SSH configuration - No rate limiting enabled
- No intrusion prevention system active during attack window
- Administrative accounts used common/default passwords

### Attack Timeline
| Time | Event | Description |
|------|-------|-------------|
| 14:30 UTC | Attack Start | First failed authentication attempt from 192.168.1.100 |
| 14:35 UTC | Attack Progression | 15 failed attempts recorded |
| 15:00 UTC | Attack Acceleration | 25 failed attempts in 30-minute window |
| 15:42 UTC | Detection | Wazuh alert triggered |
| 15:45 UTC | Containment | IP blocked, SSH disabled |
| 16:00 UTC | Eradication | SSH configuration hardened |
| 16:30 UTC | Recovery | Services restored |
| 17:00 UTC | Closure | Incident resolved |

## Recommendations

### Immediate Actions (Next 24 hours)
1. Implement Fail2Ban on all SSH servers within 24 hours
2. Review and strengthen all administrative passwords within 48 hours
3. Update firewall rules to restrict SSH access to known IPs only

### Short-term Improvements (1-4 weeks)
1. Deploy intrusion detection/prevention system (Security Team - 1 week)
2. Implement automated IP blocking for brute force attacks (DevOps - 2 weeks)
3. Conduct security awareness training for admin password policies (HR - 3 weeks)

### Long-term Enhancements (1-6 months)
1. Implement zero-trust network architecture (6 months)
2. Deploy SIEM with automated response capabilities (4 months)
3. Regular security configuration audits (quarterly)

## Incident Response Metrics

### Response Time Metrics
- **Time to Detect:** 72 minutes (from attack start to alert)
- **Time to Respond:** 3 minutes (from alert to containment)
- **Time to Contain:** 3 minutes (from alert to IP block)
- **Time to Eradicate:** 15 minutes (from containment to system hardening)
- **Time to Recover:** 30 minutes (from eradication to service restoration)

### Effectiveness Metrics
- **Data Loss:** 0% (no successful access achieved)
- **Systems Affected:** 1 primary system (web-srv-01)
- **Recovery Cost:** $2,400 (service disruption costs)

## Communication Log

| Date/Time | Contact | Method | Message Summary |
|-----------|---------|--------|-----------------|
| 2024-11-03 15:45 | IT Director | Phone | Incident notification and status update |
| 2024-11-03 16:00 | DevOps Team | Slack | Containment actions and system isolation |
| 2024-11-03 16:30 | Business Units | Email | Service restoration notification |
| 2024-11-03 17:00 | Executive Team | Email | Final incident report and recommendations |

## Approval and Sign-off

### Incident Response Team
| Name | Role | Date | Signature |
|------|------|------|-----------|
| Jane Doe | Incident Response Lead | 2024-11-03 | /s/ Jane Doe |
| John Smith | Security Analyst | 2024-11-03 | /s/ John Smith |
| Mike Johnson | IT Operations | 2024-11-03 | /s/ Mike Johnson |

### Management Approval
| Name | Role | Date | Signature |
|------|------|------|-----------|
| Sarah Wilson | IT Director | 2024-11-03 | /s/ Sarah Wilson |
| Robert Chen | CISO | 2024-11-03 | /s/ Robert Chen |

## Appendices

### Appendix A: Detailed Evidence Inventory
**Authentication Log Excerpt:**
```
Nov  3 14:30:15 web-srv-01 sshd[12345]: Failed password for admin from 192.168.1.100 port 22 ssh2
Nov  3 14:30:17 web-srv-01 sshd[12346]: Failed password for admin from 192.168.1.100 port 22 ssh2
... [45 more similar entries]
Nov  3 15:45:02 web-srv-01 sshd[12456]: Failed password for admin from 192.168.1.100 port 22 ssh2
```

**Wazuh Alert Details:**
- Rule ID: 100001
- Level: 10
- Description: Failed SSH authentication attempt
- Source IP: 192.168.1.100
- Frequency: 47 attempts in 75 minutes

### Appendix B: Technical Analysis Details
**SSH Configuration Before Incident:**
```
# /etc/ssh/sshd_config
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 6  # Default - too permissive
```

**SSH Configuration After Incident:**
```
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication yes
MaxAuthTries 3
PubkeyAuthentication yes
```

### Appendix C: Network Diagrams
[Network topology showing attack path and containment points]

### Appendix D: Timeline Visualization
[Chronological timeline with attack progression and response actions]

### Appendix E: Related Documentation
- Wazuh Alert ID: WAZUH-2024-11-03-001
- Change Request: CR-2024-11-03-SSH-HARDENING
- Security Policy Update: SP-2024-11-03-BRUTE-FORCE

---

**Document Control:**
- **Created By:** John Smith (Security Analyst)
- **Reviewed By:** Jane Doe (Incident Response Lead)
- **Approved By:** Robert Chen (CISO)
- **Next Review Date:** 2025-11-03
- **Retention Period:** 7 years per compliance requirements