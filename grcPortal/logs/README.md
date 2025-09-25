# 📋 Logs Directory

This directory contains all application logs for the GRC Portal, implementing comprehensive logging for security monitoring, audit trails, and system diagnostics.

## 📂 Directory Structure

```
logs/
├── README.md                    # This documentation
├── .gitkeep                     # Ensures directory exists in Git
├── forensics.log               # Security and forensic events
├── [application_logs]/         # Additional log files
│   ├── app.log                 # Main application log
│   ├── audit.log               # Audit trail log
│   ├── security.log            # Security events
│   └── error.log               # Application errors
└── [archived_logs]/            # Rotated and archived logs
    ├── forensics.log.2024-01-01
    ├── forensics.log.2024-01-02
    └── [additional archives]
```

## 📊 Log Types

### 🔍 Forensics Log (forensics.log)
**Primary security and forensic logging:**
- User authentication events (login/logout)
- File upload and access activities
- Evidence collection and handling
- Incident reporting and updates
- Administrative actions and role changes
- Security policy violations
- Forensic analysis activities

**Log Format:**
```
2024-12-01 10:30:15,123 [INFO] User john.doe@example.com logged in successfully from IP 192.168.1.100
2024-12-01 10:31:22,456 [INFO] User john.doe@example.com uploaded file policy_v1.pdf from IP 192.168.1.100
2024-12-01 10:32:10,789 [WARNING] Governance violation: User jane.smith@example.com attempted admin access to /admin/users
```

### 📈 Application Logs
- **app.log**: General application events and user activities
- **audit.log**: Detailed audit trail for compliance
- **security.log**: Security-related events and alerts
- **error.log**: Application errors and exceptions

## 🔧 Logging Configuration

### Python Logging Setup
```python
# Logging configuration in app.py
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/forensics.log"),
        logging.StreamHandler()  # Console output for development
    ]
)

# Create forensics logger
forensics_logger = logging.getLogger("forensics")
forensics_logger.setLevel(logging.INFO)
```

### Log Rotation
```python
# Log rotation configuration (future enhancement)
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler(
    "logs/forensics.log",
    maxBytes=10*1024*1024,  # 10MB
    backupCount=30  # Keep 30 days of logs
)
```

## 📋 Log Content Standards

### Log Entry Structure
```
Timestamp | Level | Component | User | Action | Resource | IP | Details
```

### Log Levels
- **DEBUG**: Detailed debugging information
- **INFO**: General information about application operation
- **WARNING**: Warning messages for potential issues
- **ERROR**: Error conditions that don't stop the application
- **CRITICAL**: Critical errors that may stop the application

### Security Event Categories
- **Authentication**: Login, logout, session events
- **Authorization**: Access control decisions, role checks
- **Administration**: User management, system configuration
- **Compliance**: Policy compliance events, violations
- **Security**: Security incidents, threat detection
- **Forensics**: Evidence handling, investigation activities

## 🔐 Security & Compliance

### Log Integrity
- **Tamper Detection**: Logs stored in append-only format
- **Secure Storage**: Logs encrypted at rest in production
- **Access Controls**: Restricted read access to authorized personnel
- **Backup Protection**: Encrypted log backups

### Compliance Requirements
- **Audit Trails**: Complete audit logging for SOX, GDPR compliance
- **Retention**: Configurable retention periods (7 years for critical logs)
- **Immutability**: Logs cannot be modified once written
- **Chain of Custody**: Secure handling procedures for log evidence

### Data Protection
```python
# Log sanitization - avoid sensitive data
def sanitize_log_data(data):
    """Remove sensitive information from logs"""
    sensitive_fields = ['password', 'ssn', 'credit_card']
    for field in sensitive_fields:
        if field in data:
            data[field] = '[REDACTED]'
    return data
```

## 📊 Log Analysis & Monitoring

### Real-time Monitoring
```python
# Log monitoring for security events
def monitor_security_events():
    """Monitor logs for security incidents"""
    with open("logs/forensics.log", "r") as f:
        for line in f:
            if "FAILED LOGIN" in line:
                alert_security_team("Failed login attempt detected")
            elif "ADMIN ACCESS" in line:
                log_admin_activity(line)
```

### Log Analytics
- **Event Correlation**: Link related security events
- **Trend Analysis**: Identify patterns and anomalies
- **Performance Monitoring**: Track application performance
- **Compliance Reporting**: Generate audit reports from logs

### Automated Alerts
```python
# Automated alerting based on log patterns
LOG_ALERTS = {
    "failed_login_threshold": 5,  # Alert after 5 failed logins
    "admin_action_frequency": 10,  # Alert on high admin activity
    "suspicious_ip_threshold": 3   # Alert on suspicious IP activity
}
```

## 🗂️ Log Management

### Organization
- **Naming Convention**: `component.log.YYYY-MM-DD` for rotated logs
- **Directory Structure**: Organized by date and component
- **Compression**: Automatic compression of archived logs
- **Indexing**: Log indexing for efficient searching

### Retention Policy
```python
LOG_RETENTION = {
    "forensics": 2555,  # 7 years (legal requirement)
    "audit": 2555,      # 7 years (compliance)
    "security": 1095,   # 3 years
    "application": 365, # 1 year
    "error": 90         # 90 days
}
```

### Archival Process
1. **Rotation**: Automatic log rotation based on size/time
2. **Compression**: Gzip compression for storage efficiency
3. **Encryption**: Encrypt archived logs for security
4. **Offsite Storage**: Secure offsite backup of critical logs
5. **Integrity Verification**: Hash verification of archived logs

## 🔍 Log Analysis Tools

### Built-in Analysis
```python
# Log analysis functions
def analyze_failed_logins(hours=24):
    """Analyze failed login attempts"""
    cutoff = datetime.now() - timedelta(hours=hours)
    failed_attempts = []

    with open("logs/forensics.log", "r") as f:
        for line in f:
            if "FAILED LOGIN" in line:
                timestamp = parse_timestamp(line)
                if timestamp > cutoff:
                    failed_attempts.append(parse_login_attempt(line))

    return generate_failed_login_report(failed_attempts)

def detect_suspicious_activity():
    """Detect suspicious patterns in logs"""
    patterns = {
        "brute_force": r"FAILED LOGIN.*from IP (\d+\.\d+\.\d+\.\d+)",
        "privilege_escalation": r"ADMIN ACCESS.*unexpected",
        "data_exfiltration": r"LARGE FILE DOWNLOAD.*unusual"
    }

    alerts = []
    for pattern_name, regex in patterns.items():
        matches = search_logs(regex)
        if len(matches) > THRESHOLD:
            alerts.append(generate_alert(pattern_name, matches))

    return alerts
```

### External Tools Integration
- **ELK Stack**: Elasticsearch, Logstash, Kibana for advanced analysis
- **Splunk**: Enterprise log analysis and reporting
- **SIEM Systems**: Integration with security information and event management
- **Custom Scripts**: Python scripts for specialized analysis

## 📋 Audit & Reporting

### Audit Log Generation
```python
# Structured audit logging
def log_audit_event(user, action, category, description, resource=None, success=True):
    """Log audit events for compliance"""
    audit_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user.id if user else None,
        "action": action,
        "category": category,
        "description": description,
        "resource": resource or request.path,
        "ip_address": request.remote_addr,
        "user_agent": request.headers.get('User-Agent'),
        "success": success
    }

    # Write to audit log
    with open("logs/audit.log", "a") as f:
        json.dump(audit_entry, f)
        f.write("\n")
```

### Compliance Reporting
- **SOX Reports**: Financial system access logging
- **GDPR Reports**: Data processing activity logs
- **HIPAA Reports**: Healthcare data access tracking
- **PCI DSS Reports**: Payment card data handling logs

## 🔧 Configuration

### Log Configuration
```python
# Advanced logging configuration
LOGGING_CONFIG = {
    "version": 1,
    "formatters": {
        "detailed": {
            "format": "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
        },
        "json": {
            "class": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s"
        }
    },
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": "logs/forensics.log",
            "formatter": "detailed"
        },
        "audit": {
            "class": "logging.FileHandler",
            "filename": "logs/audit.log",
            "formatter": "json"
        }
    }
}
```

### Performance Tuning
- **Asynchronous Logging**: Non-blocking log writes
- **Buffering**: Log buffering for high-volume scenarios
- **Compression**: Real-time log compression
- **Remote Logging**: Centralized logging for distributed deployments

## 🚨 Security Monitoring

### Real-time Alerts
- **Failed Authentication**: Multiple failed login attempts
- **Privilege Escalation**: Unauthorized access attempts
- **Suspicious Activity**: Unusual user behavior patterns
- **System Anomalies**: Unexpected system behavior

### Incident Response Integration
- **Automated Triage**: Log-based incident classification
- **Evidence Collection**: Automatic log preservation for incidents
- **Correlation Analysis**: Link logs across multiple systems
- **Timeline Reconstruction**: Event timeline generation from logs

## 🛠️ Maintenance

### Regular Tasks
- **Log Rotation**: Automatic log rotation and archival
- **Storage Monitoring**: Disk usage monitoring and alerting
- **Integrity Checks**: Log file integrity verification
- **Performance Tuning**: Log processing optimization

### Troubleshooting
- **Log Loss**: Recovery procedures for missing logs
- **Performance Issues**: Log processing bottleneck resolution
- **Storage Problems**: Log storage capacity management
- **Analysis Problems**: Log parsing and analysis debugging

## 🔮 Future Enhancements

### Advanced Features
- **Log Encryption**: End-to-end encrypted logging
- **Blockchain Logging**: Immutable log storage on blockchain
- **AI Analysis**: Machine learning for anomaly detection
- **Real-time Streaming**: Live log streaming and analysis
- **Distributed Logging**: Multi-node log aggregation

### Integration Capabilities
- **SIEM Integration**: Direct integration with security platforms
- **Cloud Logging**: AWS CloudWatch, Google Cloud Logging
- **Log Shipping**: Automated log forwarding to central systems
- **API Access**: RESTful APIs for log data access

---

**📋 For audit procedures, see [../docs/index.md#audit](../docs/index.md#audit)**

**🔗 Back to main project: [../README.md](../README.md)**