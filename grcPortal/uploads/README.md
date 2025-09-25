# 📁 Uploads Directory

This directory serves as the secure storage location for user-uploaded files in the GRC Portal, implementing enterprise-grade file handling with automatic cleanup and security controls.

## 🔒 Security Overview

### File Handling Security
- **Automatic Cleanup**: Files automatically deleted after 2 minutes
- **Secure Storage**: Files stored outside web root for protection
- **Access Control**: Files served through controlled Flask routes
- **Integrity Verification**: SHA-256 hashing for uploaded files
- **Type Validation**: Strict file type checking (PDF, TXT, images)

### Zero Trust Implementation
- **User Isolation**: Files accessible only to uploading user
- **Session Validation**: File access requires valid user session
- **Path Traversal Protection**: Secure filename sanitization
- **Audit Logging**: All file operations logged for compliance

## 📂 Directory Structure

```
uploads/
├── README.md                    # This documentation
├── .gitkeep                     # Ensures directory exists in Git
├── [temporary_files]/          # Auto-cleaned uploaded files
│   ├── policy_document.pdf     # Example uploaded file
│   ├── security_report.txt     # Example text document
│   └── evidence_screenshot.png # Example image evidence
└── [auto-deleted]/             # Files removed after processing
```

## 🔄 File Lifecycle

### Upload Process
1. **Client Upload**: User selects and submits file through web form
2. **Server Validation**: File type, size, and security checks
3. **Secure Storage**: File saved with sanitized filename
4. **Processing**: AI analysis or security scanning performed
5. **Automatic Cleanup**: File deleted after 2-minute retention period

### File Processing Flow
```python
# Upload handling in app.py
@app.route("/home", methods=["GET", "POST"])
@login_required
def home():
    if request.method == "POST" and "file" in request.files:
        file = request.files["file"]

        # Security validation
        if not allowed_file(file.filename):
            flash("Invalid file type", "danger")
            return redirect(url_for("home"))

        # Secure filename and path
        filename = secure_filename(file.filename)
        save_path = os.path.join("uploads", filename)

        # Save file
        file.save(save_path)

        # Create database record
        upload = Upload(user_id=session["user_id"], filename=filename)

        # Schedule automatic deletion
        delete_file_after_delay(save_path, 120)  # 2 minutes

        # Process file (AI analysis, etc.)
        scan_result = scan_file_for_grc(save_path)

        flash("File uploaded and processed securely", "success")
```

## 🛡️ Security Features

### File Type Restrictions
**Allowed Extensions:**
- `.pdf` - Portable Document Format (policies, reports)
- `.txt` - Plain text files (logs, documentation)
- `.log` - Log files (system logs, audit trails)
- `.png` - PNG images (screenshots, evidence)
- `.jpg/.jpeg` - JPEG images (photographs, diagrams)

**Security Rationale:**
- Prevents execution of malicious scripts
- Limits to document and image formats only
- Reduces attack surface for file-based exploits

### File Size Limits
- **Maximum Size**: 10MB per file (configurable)
- **Rationale**: Prevents disk space exhaustion and DoS attacks
- **Validation**: Both client-side and server-side checks

### Filename Security
```python
def secure_filename(name: str) -> str:
    """Sanitize filename to prevent path traversal"""
    # Remove path separators and dangerous characters
    name = werkzeug_secure(name)
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)
```

## 🔍 File Processing

### AI-Powered Analysis
- **Document Scanning**: LLM analysis for compliance and risk identification
- **Threat Detection**: Pattern-based security threat identification
- **Content Extraction**: Text extraction from PDFs and documents
- **Risk Generation**: Automatic risk record creation from findings

### Forensic Evidence
- **Evidence Collection**: Secure upload for incident investigation
- **Integrity Hashing**: SHA-256 hashes for tamper detection
- **Chain of Custody**: Audit trail for evidence handling
- **Access Logging**: All evidence access logged for compliance

## ⏰ Automatic Cleanup

### Retention Policy
- **Standard Files**: 2-minute retention after upload
- **Evidence Files**: Moved to `evidence/` directory for long-term storage
- **Report Files**: Generated reports stored in `reports/` directory

### Cleanup Implementation
```python
def delete_file_after_delay(file_path: str, delay_seconds: int = 120):
    """Schedule secure file deletion"""
    def delete():
        time.sleep(delay_seconds)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logging.info(f"File {file_path} auto-deleted after {delay_seconds}s")
        except Exception as e:
            logging.error(f"Error deleting file {file_path}: {e}")

    thread = threading.Thread(target=delete, daemon=True)
    thread.start()
```

## 📊 Monitoring & Analytics

### File Operation Metrics
- **Upload Volume**: Number and types of files uploaded
- **Processing Success**: Success/failure rates of file processing
- **Storage Usage**: Disk space utilization tracking
- **Security Events**: Failed uploads and security violations

### Audit Logging
```python
# Comprehensive audit logging
forensics_logger.info(
    f"User {user.email} uploaded file {filename} "
    f"from IP {request.remote_addr}"
)
```

## 🔧 Configuration

### Flask Upload Configuration
```python
# In app.py
app.config.update(
    MAX_CONTENT_LENGTH=10*1024*1024,  # 10MB limit
    UPLOAD_FOLDER="uploads"
)
```

### Directory Permissions
```bash
# Secure directory permissions
chown www-data:www-data uploads/
chmod 755 uploads/
```

## 🚨 Security Considerations

### Threat Mitigation
- **Path Traversal**: Prevented through secure_filename()
- **Directory Listing**: Disabled through web server configuration
- **Direct Access**: Files served through Flask routes only
- **Malware Upload**: Limited file types and automatic cleanup
- **DoS Protection**: File size limits and rate limiting

### Compliance Requirements
- **Data Retention**: Automatic cleanup meets privacy requirements
- **Access Logging**: Comprehensive audit trail for compliance
- **Integrity Checks**: Hash verification for evidence files
- **Secure Deletion**: Files securely removed from storage

## 🛠️ Maintenance

### Regular Tasks
- **Disk Monitoring**: Ensure sufficient storage space
- **Permission Audits**: Regular permission checks
- **Log Rotation**: Upload activity log management
- **Security Updates**: Regular security scanning

### Troubleshooting
- **Upload Failures**: Check file permissions and disk space
- **Processing Errors**: Verify file format and content
- **Cleanup Issues**: Monitor thread execution and error logs
- **Security Alerts**: Investigate suspicious upload patterns

## 📈 Performance Optimization

### Storage Optimization
- **Temporary Storage**: Fast storage for temporary files
- **Compression**: Automatic compression for large files
- **CDN Integration**: Static file serving optimization
- **Caching**: Intelligent caching for frequently accessed files

### Processing Optimization
- **Asynchronous Processing**: Background file processing
- **Queue Management**: Upload queue for high-volume scenarios
- **Resource Limits**: CPU and memory limits for processing
- **Timeout Handling**: Proper timeout handling for long-running processes

## 🔮 Future Enhancements

### Planned Features
- **Advanced Scanning**: Integration with commercial malware scanners
- **Content Analysis**: Enhanced AI content analysis capabilities
- **Bulk Upload**: Support for multiple file uploads
- **Version Control**: File versioning for policy documents
- **Collaboration**: Multi-user file sharing and annotation

### Technology Integration
- **Object Storage**: S3-compatible storage for scalability
- **CDN**: Global content delivery for distributed teams
- **AI Enhancement**: Advanced machine learning for content analysis
- **Blockchain**: Immutable evidence storage and verification

---

**📁 For file upload procedures, see [../docs/file_upload_procedure.md](../docs/file_upload_procedure.md)**

**🔗 Back to main project: [../README.md](../README.md)**