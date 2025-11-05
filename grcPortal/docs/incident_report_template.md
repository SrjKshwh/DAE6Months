# Incident Report Template - Standard Format

## Document Information

| Document ID | Version | Classification | Date Created | Incident ID |
|-------------|---------|----------------|--------------|-------------|
| IR-REP-001 | 1.0 | Confidential | [Current Date] | [Auto-generated] |

## Executive Summary

**Incident Type:** [Brief description - e.g., "Unauthorized Access Attempt", "Malware Infection", "Data Breach"]

**Severity Level:** [Critical/High/Medium/Low]

**Date/Time of Incident:** [Start and end timestamps]

**Affected Systems:** [List of impacted systems/assets]

**Business Impact:** [Brief assessment of business consequences]

**Current Status:** [Open/Contained/Eradicated/Recovered/Closed]

## Incident Details

### Detection Information
- **Detection Date/Time:** [When incident was first detected]
- **Detection Method:** [How incident was discovered - monitoring alert, user report, etc.]
- **Initial Reporter:** [Name and contact information]
- **Detection Source:** [Wazuh alert, manual review, automated scan, etc.]

### Incident Description
[Provide detailed chronological description of the incident, including:
- What occurred
- How it was discovered
- Initial scope assessment
- Any immediate actions taken]

### Affected Assets
| Asset Name | Asset Type | Criticality | Impact Level | Location |
|------------|------------|-------------|--------------|----------|
| [Asset 1] | [Server/DB/App] | [High/Med/Low] | [Severe/Moderate/Minimal] | [Physical/Virtual/Cloud] |
| [Asset 2] | [Server/DB/App] | [High/Med/Low] | [Severe/Moderate/Minimal] | [Physical/Virtual/Cloud] |

### Attack Vector Analysis
- **Primary Attack Vector:** [e.g., Phishing, Exploited Vulnerability, Unauthorized Access]
- **Compromised Credentials:** [Yes/No - specify if known]
- **Malware Involved:** [Yes/No - specify family/type if known]
- **External IP Addresses:** [List any external IPs involved]
- **Command and Control:** [Any C2 servers identified]

## Response Actions Taken

### Phase 1: Identification & Assessment
**Date/Time Started:** [Timestamp]
**Actions Taken:**
- [List specific identification steps]
- [Scope determination activities]
- [Initial evidence collection]

**Personnel Involved:**
- [Name/Role] - [Specific responsibilities]

### Phase 2: Containment
**Date/Time Started:** [Timestamp]
**Short-term Containment:**
- [Immediate isolation steps]
- [Network segmentation applied]
- [Access restrictions implemented]

**Long-term Containment:**
- [Ongoing containment measures]
- [System hardening steps]

**Tools Used:**
- VirtualBox: `VBoxManage controlvm "VM" acpipowerbutton`
- Network Isolation: `iptables -I INPUT -s [IP] -j DROP`
- Service Shutdown: `systemctl stop [service]`

### Phase 3: Eradication
**Date/Time Started:** [Timestamp]
**Root Cause Identified:** [Description of root cause]

**Eradication Steps:**
- [Malware removal procedures]
- [Vulnerability patching]
- [Credential reset activities]
- [System cleanup]

**Tools Used:**
- Malware Analysis: `volatility -f memory.dmp --profile=Win7SP1x64 pslist`
- File System Analysis: `fls -r disk_image.dd`
- Network Analysis: `tcpdump -i eth0 -w capture.pcap`

### Phase 4: Recovery
**Date/Time Started:** [Timestamp]
**System Recovery:**
- [Backup restoration procedures]
- [System rebuild activities]
- [Service restoration steps]

**Validation Steps:**
- [Integrity verification]
- [Functionality testing]
- [Security testing]

### Phase 5: Lessons Learned
**Date/Time Completed:** [Timestamp]
**Effectiveness Assessment:**
- [What worked well]
- [What could be improved]
- [Gaps identified]

**Preventive Measures:**
- [New controls implemented]
- [Policy updates]
- [Training requirements]

## Evidence Collected

### Digital Evidence
| Evidence ID | Type | Description | Collection Method | Hash Value | Chain of Custody |
|-------------|------|-------------|-------------------|------------|------------------|
| EV-001 | Memory Dump | Full system memory capture | LiME kernel module | [SHA256] | Collected by [Name] on [Date] |
| EV-002 | Disk Image | Forensic disk image | dc3dd | [SHA256] | Collected by [Name] on [Date] |
| EV-003 | Network Capture | Traffic during incident | tcpdump | [SHA256] | Collected by [Name] on [Date] |

### Log Evidence
| Log Source | Time Range | Key Events | Location |
|------------|------------|------------|----------|
| Wazuh Agent | [Start-End] | Authentication failures | /var/log/wazuh/alerts.log |
| System Auth | [Start-End] | Failed login attempts | /var/log/auth.log |
| Firewall | [Start-End] | Blocked connections | /var/log/ufw.log |

### Physical Evidence
[List any physical evidence collected - screenshots, photos, etc.]

## Impact Assessment

### Technical Impact
- **System Availability:** [Downtime duration, affected services]
- **Data Integrity:** [Data corruption/loss assessment]
- **System Performance:** [Performance degradation noted]

### Business Impact
- **Financial Loss:** [Direct costs, lost productivity]
- **Operational Disruption:** [Business process impact]
- **Customer Impact:** [Affected customers, service degradation]

### Compliance Impact
- **Regulatory Requirements:** [GDPR, HIPAA, PCI-DSS implications]
- **Notification Requirements:** [Breach notification obligations]
- **Audit Findings:** [Potential compliance violations]

## Root Cause Analysis

### Technical Root Cause
[Detailed technical analysis of how the incident occurred]

### Contributing Factors
- [Factor 1] - [Impact level]
- [Factor 2] - [Impact level]
- [Factor 3] - [Impact level]

### Attack Timeline
| Time | Event | Description |
|------|-------|-------------|
| [HH:MM] | Initial Compromise | [Description] |
| [HH:MM] | Lateral Movement | [Description] |
| [HH:MM] | Data Exfiltration | [Description] |
| [HH:MM] | Detection | [Description] |

## Recommendations

### Immediate Actions (Next 24 hours)
1. [Action 1 with timeline]
2. [Action 2 with timeline]
3. [Action 3 with timeline]

### Short-term Improvements (1-4 weeks)
1. [Improvement 1 with owner]
2. [Improvement 2 with owner]
3. [Improvement 3 with owner]

### Long-term Enhancements (1-6 months)
1. [Enhancement 1 with timeline]
2. [Enhancement 2 with timeline]
3. [Enhancement 3 with timeline]

## Incident Response Metrics

### Response Time Metrics
- **Time to Detect:** [Duration from incident start to detection]
- **Time to Respond:** [Duration from detection to initial response]
- **Time to Contain:** [Duration from detection to containment]
- **Time to Eradicate:** [Duration from containment to eradication]
- **Time to Recover:** [Duration from eradication to recovery]

### Effectiveness Metrics
- **Data Loss:** [Amount of data compromised]
- **Systems Affected:** [Number of systems impacted]
- **Recovery Cost:** [Total cost of incident response and recovery]

## Communication Log

| Date/Time | Contact | Method | Message Summary |
|-----------|---------|--------|-----------------|
| [Date] | [Stakeholder] | [Email/Phone/Meeting] | [Summary] |
| [Date] | [Stakeholder] | [Email/Phone/Meeting] | [Summary] |

## Approval and Sign-off

### Incident Response Team
| Name | Role | Date | Signature |
|------|------|------|-----------|
| [Name] | Incident Response Lead | [Date] | ___________ |
| [Name] | Security Analyst | [Date] | ___________ |
| [Name] | IT Operations | [Date] | ___________ |

### Management Approval
| Name | Role | Date | Signature |
|------|------|------|-----------|
| [Name] | IT Director | [Date] | ___________ |
| [Name] | CISO | [Date] | ___________ |

## Appendices

### Appendix A: Detailed Evidence Inventory
[Complete list of all evidence collected with metadata]

### Appendix B: Technical Analysis Details
[Detailed technical findings, code analysis, etc.]

### Appendix C: Network Diagrams
[Before/after network topology diagrams]

### Appendix D: Timeline Visualization
[Detailed chronological timeline with all events]

### Appendix E: Related Documentation
[Links to related incident reports, change records, etc.]

---

**Document Control:**
- **Created By:** [Name]
- **Reviewed By:** [Name]
- **Approved By:** [Name]
- **Next Review Date:** [Date + 1 year]
- **Retention Period:** [7 years per compliance requirements]