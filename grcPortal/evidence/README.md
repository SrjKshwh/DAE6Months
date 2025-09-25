# 🔍 Evidence Directory

This directory serves as the secure repository for digital evidence collected during incident response and forensic investigations in the GRC Portal, implementing chain of custody and integrity verification.

## 📂 Directory Structure

```
evidence/
├── README.md                    # This documentation
├── .gitkeep                     # Ensures directory exists in Git
├── [incident_evidence]/         # Evidence organized by incident
│   ├── incident_001/
│   │   ├── evidence_001.pdf     # Collected evidence file
│   │   ├── evidence_001.hash    # Integrity hash file
│   │   ├── evidence_001.meta    # Metadata file
│   │   └── chain_of_custody.log # Custody tracking
│   └── incident_002/
│       └── [similar structure]
└── [archived_evidence]/         # Long-term evidence storage
    └── [archived_incidents]/
```

## 🔐 Security & Integrity

### Evidence Integrity
- **SHA-256 Hashing**: Cryptographic hashing for tamper detection
- **Digital Signatures**: Evidence signed to prove authenticity
- **Chain of Custody**: Complete audit trail of evidence handling
- **Access Logging**: All evidence access logged for compliance

### Access Controls
- **Role-Based Access**: Restricted to authorized forensic investigators
- **Need-to-Know**: Access limited to assigned personnel
- **Session Logging**: All access sessions recorded
- **Encryption**: Evidence encrypted at rest and in transit

## 📋 Evidence Collection Process

### Automated Collection
```python
# Evidence collection in forensics route
@app.route("/forensics", methods=["POST"])
@login_required
def forensics():
    if "collect_evidence" in request.form:
        # Collect evidence metadata
        evidence_type = request.form.get("evidence_type")
        description = request.form.get("description")
        storage_method = request.form.get("storage_method", "Secure server storage")
        incident_id = request.form.get("incident_id")

        file_path = None
        hash_value = None

        # Handle file upload
        if "evidence_file" in request.files:
            file = request.files["evidence_file"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                evidence_dir = "evidence"
                Path(evidence_dir).mkdir(exist_ok=True)

                # Create incident-specific directory
                incident_dir = f"incident_{incident_id}" if incident_id else "general"
                full_dir = os.path.join(evidence_dir, incident_dir)
                Path(full_dir).mkdir(exist_ok=True)

                file_path = os.path.join(full_dir, filename)
                file.save(file_path)

                # Generate integrity hash
                hash_value = compute_file_hash(file_path)

                # Create metadata file
                create_evidence_metadata(file_path, {
                    "type": evidence_type,
                    "description": description,
                    "collector": current_user().email,
                    "collection_time": datetime.now(timezone.utc),
                    "hash": hash_value
                })

                forensics_logger.info(f"Evidence collected: {file_path}")

        # Create database record
        evidence = Evidence(
            type=EvidenceType(evidence_type),
            file_path=file_path,
            description=description,
            collected_by=current_user().id,
            storage_method=storage_method,
            hash_value=hash_value,
            incident_id=int(incident_id) if incident_id else None
        )
        db.add(evidence)
        db.commit()

        flash("Evidence collected successfully.", "success")
```

### Evidence Metadata
```json
{
  "evidence_id": "EVD-2024-001",
  "type": "file_system",
  "description": "Suspicious file found in user directory",
  "collector": "john.doe@company.com",
  "collection_time": "2024-12-01T10:30:00Z",
  "collection_method": "Automated forensic tool",
  "storage_location": "/evidence/incident_123/evidence_001.pdf",
  "integrity_hash": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
  "file_size": 2457600,
  "mime_type": "application/pdf",
  "chain_of_custody": [
    {
      "action": "collected",
      "actor": "john.doe@company.com",
      "timestamp": "2024-12-01T10:30:00Z",
      "location": "Forensic workstation WS-001"
    }
  ]
}
```

## 📊 Evidence Management

### Evidence Types
- **Digital Files**: Documents, logs, configuration files
- **Screenshots**: System state captures, error messages
- **Network Logs**: Traffic captures, connection logs
- **System Images**: Memory dumps, disk images
- **Database Records**: Extracted database content
- **Configuration Files**: System and application configurations

### Organization Structure
```
evidence/
├── incident_{id}/           # Incident-specific evidence
│   ├── evidence_{seq}.ext   # Original evidence file
│   ├── evidence_{seq}.hash  # Integrity verification
│   ├── evidence_{seq}.meta  # Metadata JSON
│   └── custody.log          # Chain of custody log
├── archived/                # Long-term storage
└── temp/                    # Temporary processing area
```

## 🔗 Chain of Custody

### Custody Tracking
```python
def update_chain_of_custody(evidence_id, action, actor, location=None):
    """Update evidence chain of custody"""
    custody_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,  # collected, transferred, analyzed, archived
        "actor": actor,
        "location": location or "Digital forensics lab",
        "evidence_id": evidence_id,
        "verification_hash": compute_file_hash(get_evidence_path(evidence_id))
    }

    # Append to custody log
    custody_log = get_custody_log_path(evidence_id)
    with open(custody_log, "a") as f:
        json.dump(custody_entry, f, indent=2)
        f.write("\n")

    # Log to audit system
    log_audit_event(actor, "EVIDENCE_CUSTODY_UPDATE",
                   f"Evidence {evidence_id}: {action}")
```

### Custody Actions
- **Collected**: Initial evidence gathering
- **Transferred**: Movement between systems/locations
- **Analyzed**: Evidence examination and processing
- **Presented**: Evidence used in reports or court
- **Archived**: Long-term storage
- **Destroyed**: Secure deletion when no longer needed

## 🔍 Forensic Analysis

### Analysis Tools Integration
- **File Analysis**: Metadata extraction, content analysis
- **Hash Verification**: Integrity checking and comparison
- **Timeline Creation**: Event reconstruction and correlation
- **Pattern Recognition**: Automated anomaly detection
- **Report Generation**: Court-admissible forensic reports

### Analysis Workflow
1. **Evidence Intake**: Secure collection and hashing
2. **Preliminary Analysis**: Basic file and metadata examination
3. **Detailed Analysis**: In-depth forensic examination
4. **Correlation**: Linking evidence across multiple sources
5. **Reporting**: Comprehensive forensic report generation
6. **Archival**: Secure long-term storage

## 📋 Compliance & Legal

### Legal Standards
- **Chain of Custody**: Maintained throughout evidence lifecycle
- **Integrity Protection**: Cryptographic hashing and digital signatures
- **Access Controls**: Need-to-know access with audit logging
- **Retention Policies**: Configurable retention based on evidence type
- **Destruction Procedures**: Secure deletion with verification

### Regulatory Compliance
- **GDPR**: Data protection for personal information in evidence
- **SOX**: Financial system evidence handling
- **HIPAA**: Healthcare data protection in medical incidents
- **PCI DSS**: Payment card data security
- **ISO 27037**: Digital evidence handling standards

## 🔐 Security Measures

### Encryption
- **At Rest**: AES-256 encryption for stored evidence
- **In Transit**: TLS 1.3 for evidence transfer
- **Database**: Encrypted evidence metadata
- **Backups**: Encrypted backup storage

### Access Security
```python
# Evidence access control
def can_access_evidence(user, evidence):
    # Check user role and permissions
    if user.role not in ["admin", "auditor"]:
        return False

    # Check incident assignment
    if evidence.incident and evidence.incident.reported_by != user.id:
        if user.role != "admin":
            return False

    # Log access for audit
    log_evidence_access(user, evidence, "accessed")

    return True
```

### Integrity Verification
```python
def verify_evidence_integrity(evidence_path, stored_hash):
    """Verify evidence file integrity"""
    current_hash = compute_file_hash(evidence_path)
    return current_hash == stored_hash
```

## 📈 Monitoring & Audit

### Access Logging
- **All Access**: Every evidence access logged with timestamp
- **User Tracking**: User ID, IP address, and session information
- **Action Recording**: View, download, modify, delete actions
- **Audit Reports**: Regular audit reviews of evidence access

### Integrity Monitoring
- **Hash Verification**: Regular integrity checks of stored evidence
- **Anomaly Detection**: Unusual access patterns flagged
- **Storage Monitoring**: Disk space and file system health
- **Backup Verification**: Backup integrity and restoration testing

## 🗂️ Lifecycle Management

### Retention Policies
```python
EVIDENCE_RETENTION = {
    "criminal": 7 * 365,     # 7 years for criminal cases
    "civil": 5 * 365,        # 5 years for civil cases
    "regulatory": 7 * 365,   # 7 years for regulatory matters
    "operational": 3 * 365,  # 3 years for operational incidents
    "general": 1 * 365       # 1 year for general evidence
}
```

### Archival Process
1. **Assessment**: Determine retention requirements
2. **Verification**: Final integrity check before archival
3. **Encryption**: Additional encryption for long-term storage
4. **Transfer**: Move to secure archival storage
5. **Indexing**: Update archival database records
6. **Destruction**: Secure deletion from active storage

### Destruction Process
1. **Authorization**: Management approval for destruction
2. **Verification**: Final integrity and custody verification
3. **Secure Deletion**: Cryptographic erasure methods
4. **Certificate**: Destruction certificate generation
5. **Audit**: Final audit log entry

## 🛠️ Maintenance

### Regular Tasks
- **Integrity Checks**: Daily hash verification of all evidence
- **Storage Monitoring**: Disk usage and capacity planning
- **Access Audits**: Monthly review of access logs
- **Retention Reviews**: Quarterly retention policy compliance

### Backup Strategy
- **Daily Backups**: Incremental backups of active evidence
- **Weekly Full**: Complete backup of all evidence
- **Offsite Storage**: Encrypted backups in secure locations
- **Testing**: Regular backup restoration testing

## 🔮 Future Enhancements

### Advanced Features
- **Blockchain Custody**: Immutable chain of custody on blockchain
- **AI Analysis**: Machine learning for evidence correlation
- **Automated Collection**: IoT device evidence gathering
- **Cloud Forensics**: Multi-cloud evidence collection
- **Collaborative Analysis**: Multi-agency evidence sharing

### Integration Capabilities
- **Digital Forensics Tools**: Integration with EnCase, FTK, Autopsy
- **SIEM Correlation**: Security event correlation with evidence
- **Case Management**: Integration with legal case management systems
- **Court Presentation**: Direct court presentation capabilities

---

**🔍 For forensic procedures, see [../docs/playbooks.md](../docs/playbooks.md)**

**🔗 Back to main project: [../README.md](../README.md)**