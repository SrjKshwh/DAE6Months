# GRC Portal - Governance, Risk, and Compliance Documentation

## 1. NIST RMF Risk Management Terms

### Asset (Information/Resource)
- **Definition**: Any information or system resource that has value to the organization
- **Examples**: Customer data, intellectual property, hardware, software systems
- **In Code**: `asset: Mapped[str] = mapped_column(String(500), nullable=False)`

### Threat
- **Definition**: Any circumstance or event that has the potential to violate security
- **Examples**: Malware, unauthorized access, natural disasters, insider threats
- **In Code**: `threat: Mapped[str] = mapped_column(String(500), nullable=False)`

### Vulnerability
- **Definition**: Weakness in an information system, system security procedures, or implementation that could be exploited
- **Examples**: Unpatched software, weak passwords, misconfigurations
- **In Code**: `vulnerability: Mapped[str] = mapped_column(String(500), nullable=False)`

### Control (Safeguard/Countermeasure)
- **Definition**: Protective measure that mitigates risk by reducing likelihood or impact
- **Examples**: Firewalls, access controls, encryption, security policies
- **In Code**: `control: Mapped[str] = mapped_column(String(500), nullable=False)`

## 2. Database Schema Analysis

### Risk Model Capacity
The enhanced Risk model supports comprehensive risk management:

```python
class Risk(Base):
    # Core RMF fields
    asset, threat, vulnerability, control

    # Compliance mapping
    compliance_standard: ComplianceFramework
    category: RiskCategory

    # Risk scoring (1-5 scale)
    likelihood, impact, score
    severity: RiskSeverity

    # Financial impact
    ale, emv  # Annualized Loss Expectancy, Expected Monetary Value

    # Risk management
    mitigation_plan, residual_risk, owner
    status: RiskStatus
```

**Supported Risk Categories:**
- Access Control
- Incident Response
- Audit & Logging
- Configuration Management
- Cryptography
- Data Protection
- Network Security
- Physical Security
- Personnel Security
- Supply Chain
- Vulnerability Management

**Supported Compliance Frameworks:**
- NIST SP 800-53
- NIST CSF
- ISO 27001/27002
- PCI DSS
- HIPAA
- SOX
- GDPR
- CIS Controls
- COBIT

## 3. Defense in Depth Strategy - 3 Layers

### Layer 1: Perimeter/Network Security
- **Flask Security Headers**: `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SECURE`
- **Input Validation**: Email regex validation, password complexity checks
- **File Upload Security**: Extension validation, secure filename sanitization
- **Rate Limiting**: Not implemented (recommendation for production)

### Layer 2: Application Security
- **Authentication**: Password hashing with Werkzeug, session management
- **Authorization**: `@login_required` decorator for protected routes
- **Data Sanitization**: SQL injection prevention via SQLAlchemy ORM
- **Error Handling**: Custom 404/500 error pages, secure error messages
- **Logging**: Structured logging without sensitive data

### Layer 3: Data/Storage Security
- **Database Security**: SQLAlchemy ORM prevents SQL injection
- **File Security**: Automatic file deletion after 2 minutes
- **Environment Security**: API keys loaded from `.env` file
- **Session Security**: Secure session configuration, auto-logout

## 4. Zero Trust Implementation

### Application Layer Access Control
```python
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please login first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper
```

### Database Layer Access Control
```python
# In scan route - verify ownership
if not up or up.user_id != session.get("user_id"):
    flash("Upload not found or unauthorized.", "danger")
    return redirect(url_for("home"))
```

### Additional Zero Trust Features Implemented:
1. **Session Validation**: Every request checks for valid user session
2. **Resource Ownership**: Database queries filter by user_id
3. **Input Validation**: All user inputs validated before processing
4. **Secure File Handling**: Files validated and automatically cleaned up
5. **API Key Protection**: Sensitive keys stored securely in environment

## 5. Risk Generation from Scan Results

### Process Flow:
1. **File Upload** → User uploads PDF/TXT security policy
2. **Text Extraction** → PyPDF2 or file.read() extracts content
3. **AI Analysis** → OpenRouter API analyzes for compliance gaps
4. **Risk Creation** → Automatic Risk entries for identified issues
5. **Compliance Mapping** → Failed controls linked to risks

### Risk Entry Structure:
```python
risk = Risk(
    asset="Uploaded Policy Document",
    threat=risk_item.get("risk", "Unspecified threat"),
    vulnerability="Policy gap or missing control",
    control="Implement recommended security control",
    compliance_standard=ComplianceFramework.NIST_SP_800_53,
    status=RiskStatus.OPEN,
    category=RiskCategory.CONFIGURATION,
    likelihood=3, impact=3,  # Default medium
    severity=severity  # Auto-calculated
)
```

### Compliance Entry Structure:
```python
compliance = Compliance(
    framework=ComplianceFramework.NIST_SP_800_53,
    control=compliance_item.get("control", "Unknown Control"),
    control_family=control.split("-")[0] if "-" in control else "XX",
    score=0.0,  # Failed control
    status="non-compliant",
    risk_id=risk.id
)
```

## 6. Risk Assessment Functions

### Built-in Risk Calculations:
```python
def calculate_score(self):
    """Calculate risk score using likelihood × impact"""
    self.score = self.likelihood * self.impact
    # Auto-determine severity
    if self.score >= 20: self.severity = RiskSeverity.CRITICAL
    elif self.score >= 12: self.severity = RiskSeverity.HIGH
    elif self.score >= 6: self.severity = RiskSeverity.MEDIUM
    else: self.severity = RiskSeverity.LOW

def calculate_ale(self, asset_value: float = 100000.0):
    """Annualized Loss Expectancy"""
    self.ale = (self.likelihood / 5.0) * (self.impact / 5.0) * asset_value

def calculate_emv(self, mitigation_cost: float = 0.0):
    """Expected Monetary Value"""
    self.emv = self.ale - mitigation_cost
```

## 7. Security Features Summary

### Authentication & Authorization
- Password hashing with Werkzeug
- Session-based authentication
- Role-based access control (basic user/admin)
- Secure logout with session clearing

### Data Protection
- SQLAlchemy ORM prevents SQL injection
- Input validation and sanitization
- Secure file upload with automatic cleanup
- Environment variable protection for secrets

### Compliance Monitoring
- Automated risk identification from policy documents
- Compliance framework mapping
- Risk scoring and severity assessment
- Audit trail with timestamps

### Operational Security
- Structured logging
- Error handling without information disclosure
- File system security with temporary file management
- Database connection security

This implementation provides a solid foundation for GRC management with comprehensive risk assessment, compliance tracking, and security controls following industry best practices.