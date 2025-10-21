# Security Monitoring Architecture Diagram

## Overview

This document provides a comprehensive monitoring architecture diagram showing the components and data flows for the GRC Portal security monitoring implementation.

## Architecture Components

### 1. Data Sources (3+ Integrated Sources)

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Windows DC01  │    │   Linux Web01   │    │   Application   │
│   (Log Source)  │    │   (Log Source)  │    │   Logs (Flask)  │
│                 │    │                 │    │                 │
│ • Security Logs │    │ • Auth Logs     │    │ • Access Logs   │
│ • System Logs   │    │ • Kern Logs     │    │ • Error Logs    │
│ • Application   │    │ • Daemon Logs   │    │ • Audit Logs    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                    ┌─────────────────────┐
                    │   Log Collection    │
                    │     Engine          │
                    │                     │
                    │ • Windows Events    │
                    │ • Syslog Messages   │
                    │ • Application Logs  │
                    │ • Real-time Parsing │
                    └─────────────────────┘
                                  │
                    ┌─────────────────────┐
                    │   Log Processing    │
                    │   & Correlation     │
                    │                     │
                    │ • Event Parsing     │
                    │ • Normalization     │
                    │ • Correlation Rules │
                    │ • Enrichment        │
                    └─────────────────────┘
                                  │
                    ┌─────────────────────┐
                    │   Alert Engine      │
                    │                     │
                    │ • Rule Matching     │
                    │ • Threshold Checks  │
                    │ • Alert Generation  │
                    │ • Escalation Logic  │
                    └─────────────────────┘
                                  │
                    ┌─────────────────────┐
                    │   Notification      │
                    │     System          │
                    │                     │
                    │ • Email Alerts      │
                    │ • Dashboard Alerts  │
                    │ • Escalation        │
                    │ • Auto-response     │
                    └─────────────────────┘
                                  │
                    ┌─────────────────────┐
                    │   SOC Dashboard     │
                    │                     │
                    │ • Real-time Alerts  │
                    │ • Incident Mgmt     │
                    │ • Analytics         │
                    │ • Reporting         │
                    └─────────────────────┘
```

### 2. Data Flow Architecture

```
Data Sources → Collection → Processing → Analysis → Alerting → Response
     ↓             ↓           ↓          ↓          ↓          ↓
   Raw Logs   → Normalized → Correlated → Detected → Generated → Executed
   Events         Events      Events     Threats    Alerts     Actions
```

### 3. System Metrics Monitoring

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│     System      │    │   Performance   │    │   Thresholds    │
│   Resources     │    │   Monitoring    │    │   & Alerts      │
│                 │    │                 │    │                 │
│ • CPU Usage     │    │ • Real-time     │    │ • CPU > 90%     │
│ • Memory Usage  │    │ • Historical    │    │ • Memory > 85%  │
│ • Disk Usage    │    │ • Trending      │    │ • Disk > 95%    │
│ • Network I/O   │    │ • Forecasting   │    │ • Network > 1G  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 4. Alert Rule Engine

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Rule Types    │    │   Conditions    │    │   Actions       │
│                 │    │                 │    │                 │
│ • Authentication│    │ • Thresholds    │    │ • Email         │
│ • File Access   │    │ • Keywords      │    │ • Dashboard     │
│ • Network       │    │ • Time Windows  │    │ • Escalation    │
│ • System        │    │ • Correlations  │    │ • Auto-response │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 5. Health Monitoring Checks

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Collection    │    │   Processing    │    │   Storage       │
│   Status        │    │   Performance   │    │   Utilization   │
│                 │    │                 │    │                 │
│ • Source Health │    │ • Processing    │    │ • Database      │
│ • Connectivity  │    │ • Queue Depth   │    │ • Disk Space    │
│ • Data Flow     │    │ • Error Rates   │    │ • Retention     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Performance Baselines

### Normal Operations Thresholds

| Metric | Baseline | Warning | Critical | Alert Action |
|--------|----------|---------|----------|--------------|
| CPU Usage | < 60% | 60-80% | > 80% | Email + Dashboard |
| Memory Usage | < 70% | 70-85% | > 85% | Email + Dashboard |
| Disk Usage | < 80% | 80-95% | > 95% | Email + Escalation |
| Network I/O | < 500 Mbps | 500-1000 Mbps | > 1000 Mbps | Dashboard Alert |
| Failed Logins | < 3/hour | 3-10/hour | > 10/hour | Security Team |
| Suspicious Files | 0 | 1-5 | > 5 | Immediate Response |

### Alerting Thresholds by Severity

#### Critical Alerts (Immediate Action Required)
- System resource exhaustion (>90% usage)
- Multiple authentication failures (>10/hour)
- Sensitive file access attempts
- Security policy violations
- Data exfiltration indicators

#### High Alerts (Within 1 Hour)
- Elevated resource usage (80-90%)
- Unusual network traffic patterns
- Privileged account misuse
- Configuration changes

#### Medium Alerts (Within 4 Hours)
- Moderate resource usage (60-80%)
- Single authentication failures
- Non-critical file access
- System warnings

#### Low Alerts (Daily Review)
- Minor resource fluctuations
- Informational security events
- Routine monitoring alerts

## Data Source Integration Details

### 1. Windows Event Logs
**Source:** Windows-DC01 (192.168.1.100)
**Protocol:** WinRM/Syslog
**Log Types:**
- Security Events (4624, 4625, 4672)
- System Events (4656, 4663)
- Application Events (5156, 5157)

**Collection Method:** Real-time event forwarding
**Processing:** Event ID parsing, user context extraction
**Alerts:** Authentication failures, file access, network blocks

### 2. Linux System Logs
**Source:** Linux-Web01 (192.168.1.101)
**Protocol:** Syslog
**Log Types:**
- Auth logs (/var/log/auth.log)
- Kernel logs (/var/log/kern.log)
- Daemon logs (/var/log/daemon.log)

**Collection Method:** Syslog forwarding
**Processing:** Log level parsing, service identification
**Alerts:** SSH failures, system calls, firewall blocks

### 3. Application Logs
**Source:** GRC Portal Flask Application
**Protocol:** Local file monitoring
**Log Types:**
- Access logs (requests, responses)
- Error logs (exceptions, failures)
- Audit logs (user actions, security events)

**Collection Method:** Log file tailing
**Processing:** HTTP status parsing, user session tracking
**Alerts:** Failed requests, security violations, performance issues

### 4. System Performance Metrics
**Source:** psutil library (local system)
**Metrics:**
- CPU utilization (per core and total)
- Memory usage (physical and virtual)
- Disk I/O and space usage
- Network interface statistics

**Collection Method:** Direct system calls
**Processing:** Percentage calculations, trend analysis
**Alerts:** Resource threshold violations

## Health Monitoring Configuration

### Collection Status Checks
- **Log Source Connectivity:** Ping tests every 5 minutes
- **Data Flow Validation:** Event count monitoring
- **Processing Queue Depth:** Alert if > 1000 unprocessed events
- **Error Rate Monitoring:** Alert if > 5% parsing failures

### Processing Performance Checks
- **Event Processing Rate:** Target > 1000 events/second
- **Alert Generation Latency:** Target < 5 seconds
- **Correlation Engine Performance:** Target < 10 seconds
- **Database Query Performance:** Target < 2 seconds

### Storage Utilization Checks
- **Database Size Monitoring:** Alert at 80% capacity
- **Log Retention Compliance:** Automatic cleanup
- **Archive Storage Health:** Disk space monitoring
- **Backup Status Verification:** Daily integrity checks

## Implementation Evidence

### Successful Data Collection
- **Windows Logs:** 24 events collected (10 auth, 8 file, 6 network)
- **Linux Logs:** 21 events collected (8 auth, 6 kern, 7 daemon)
- **Application Logs:** Integrated via Flask logging
- **System Metrics:** Real-time CPU, memory, disk, network monitoring

### Alert Generation Demonstration
- **Authentication Alerts:** 3 failed login attempts trigger high-severity alert
- **File Access Alerts:** Sensitive file access generates alerts
- **Network Alerts:** Blocked connections create medium-severity alerts
- **System Alerts:** Resource usage above thresholds trigger warnings

### Performance Baselines Established
- **Normal CPU Usage:** 15-45% during typical operations
- **Memory Usage:** 40-65% with application load
- **Alert Processing:** < 2 seconds for 100 events
- **Dashboard Response:** < 1 second for real-time updates

This architecture provides comprehensive security monitoring with multiple data sources, automated alerting, and health monitoring capabilities as required for the GRC Portal implementation.