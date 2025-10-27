# GRC Portal - Enterprise Governance, Risk, and Compliance Platform

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/flask-3.0+-blue.svg)](https://flask.palletsprojects.com/)
[![SQLAlchemy](https://img.shields.io/badge/sqlalchemy-2.0+-blue.svg)](https://www.sqlalchemy.org/)
[![Security](https://img.shields.io/badge/security-Zero%20Trust-green.svg)]()

A comprehensive enterprise-grade Governance, Risk, and Compliance (GRC) portal built with Flask and Python. This AI-powered platform provides advanced tools for risk management, compliance automation, incident response, digital forensics, and continuous monitoring capabilities. Features LLM integration for document analysis, automated risk assessment, and intelligent mitigation planning.

[Watch the demo video](https://youtu.be/cZsnQvWXJZU)

## Overview (short introduction)
The video showcases the **core functionality** of the GRC Portal, demonstrating how AI analyzes uploaded policy documents to automatically identify **compliance gaps, risks, and mitigation strategies**.

## 1. File Upload & Scanning (0:02–0:43)
- User logs into the GRC Portal and uploads `sample_risk_policy.txt`.  
- After clicking **“Scan File”**, the AI initiates document analysis.

## 2. Scan Results & Compliance Hits (0:44–1:02)
- **Summary:** Policy enforces MFA, privileged account approval, and anti-virus controls.  
- **Compliance Mapping:**
  - NIST SP 800-53: AC-2, AC-17, IR-4  
  - ISO/IEC 27001: A.8, A.16  
  - CIS Controls v8: 5, 6, 17  
- **Identified Risks (Low Severity):**
  - Inconsistent MFA on SaaS tools  
  - Vendor certifications not revalidated annually  
  - No IR tabletop exercises in 18 months  
  - Delayed quarterly access reviews  

## 3. Risk Assessment & Mitigation (1:03–2:09)
- **Risk Score:** 9 (Likelihood 3 × Impact 3) → Low Risk  
- **Visualization:** Heat map and multi-criteria breakdown (Financial, Operational, Compliance, Reputation).  
- **Mitigation Plan:**
  - Recommended Control: Comprehensive MFA gap assessment  
  - Strategies:
    - *Mitigate:* $25K, 6 months  
    - *Avoid:* $5K, 2 months  
  - **Cost-Benefit:** ROI 150%, payback 8 months  
  - **Roadmap:** Planning → Implementation → Testing → Monitoring  
  - **Metrics:** Risk score reduction (15→3), 50% incident drop  

## 4. Navigation & Reporting (2:16–3:10)
- User views the **Risk Dashboard** and **Enterprise Risk Register** (10 total risks).  
- Explores alternative risk identification methods (Brainstorming, SWOT).  
- Generates a detailed **PDF Risk Assessment Report**.

**Summary:**  
The GRC Portal automates compliance mapping and risk evaluation through AI-driven document analysis, delivering structured reports, actionable mitigation plans, and quantifiable ROI insights (this project is designed from scrath).

---

## 🌟 Key Features

### 🤖 AI-Powered Risk Intelligence
- **LLM Integration**: Advanced document analysis using OpenRouter API with GPT models
- **Automated Risk Assessment**: AI-generated compliance and risk analysis from policy documents
- **Intelligent Mitigation Planning**: AI-assisted comprehensive mitigation strategies with cost-benefit analysis
- **Communication Strategy Generation**: Automated stakeholder communication planning with tailored messaging
- **Pattern-based Threat Detection**: Automated detection of security threats in uploaded documents

### 📊 Enterprise Risk Management
- **Multi-Framework Support**: NIST RMF, ISO 31000, COSO ERM, PCI DSS, HIPAA, GDPR, CIS Controls, COBIT
- **Advanced Risk Scoring**: Multi-criteria analysis (Financial, Operational, Compliance, Reputation)
- **Risk Program Management**: Complete lifecycle from planning to monitoring
- **Gap Analysis**: Automated gap identification and remediation tracking

### 🔍 Continuous Monitoring & Analytics
- **Risk Indicators & KPIs**: Real-time monitoring with automated alerting
- **Environmental Change Detection**: Proactive risk adjustment for external changes
- **Business Impact Analysis**: RTO/RPO/MTD calculations with financial modeling
- **Predictive Analytics**: Trend analysis and risk forecasting

### 🛡️ Advanced Security Features
- **Zero Trust Architecture**: Complete implementation across all layers with session management
- **Digital Forensics**: Evidence collection with integrity hashing and chain of custody
- **Incident Response**: IRP tracking with automated evidence management and compliance incidents
- **Audit Trail**: Comprehensive security event logging and compliance reporting
- **Malware Analysis**: Automated malware analysis with behavioral indicators and threat intelligence
- **IoC Analysis**: Indicator of compromise analysis with threat actor correlation
- **Phishing Template Management**: Security awareness templates for phishing prevention
- **Vulnerability Scanning**: Integration with vulnerability scanning tools and risk assessment

### 🎯 Risk Identification Methods
- **Brainstorming Sessions**: Facilitated sessions with participant tracking and idea management
- **Risk Checklists**: Industry-standard templates with automated scoring
- **SWOT Analysis**: Strategic risk assessment with matrix-based interface
- **Critical Asset Register**: Asset inventory with risk exposure analysis
- **Environmental Change Detection**: Proactive risk adjustment for external changes

## 🛡️ Cybersecurity Risk Mitigation

grcPortal addresses critical cybersecurity risks through integrated tools and Zero Trust principles:

### Core Risk Areas Addressed

#### 1. **Unauthorized Access & Authentication Breaches**
- Zero Trust session management with automatic timeouts
- Role-based access control (Admin, Auditor, User roles)
- IP-based access restrictions and device fingerprinting
- Comprehensive authentication audit logging

#### 2. **Data Breaches & Confidentiality Violations**
- Secure file upload with type validation and automatic cleanup
- Digital evidence collection with integrity hashing
- Encrypted data handling and access controls
- Chain of custody tracking for forensic investigations

#### 3. **Malware Infections & System Compromise**
- Automated malware analysis with behavioral indicators
- Threat family identification and mitigation recommendations
- Integration with threat intelligence feeds
- Real-time detection rule creation and monitoring

#### 4. **Phishing & Social Engineering Attacks**
- IoC analysis with threat actor correlation
- Phishing template management for security awareness
- Email and URL analysis with confidence scoring
- Social engineering technique mapping and prevention

#### 5. **Compliance Violations & Regulatory Risks**
- Multi-framework compliance automation (NIST, ISO, GDPR, PCI DSS, HIPAA, SOX, CIS Controls, COBIT)
- Automated gap analysis and remediation tracking
- Compliance score monitoring and reporting
- Regulatory requirement traceability
- Compliance obligation management with risk assessment
- Compliance risk assessments and incident tracking

#### 6. **Incident Response Failures**
- Structured IRP workflows with phase tracking
- Automated evidence collection and analysis
- Incident severity classification and escalation
- Post-incident lessons learned documentation

#### 7. **Risk Oversight & Strategic Management**
- AI-powered risk identification and scoring
- Executive dashboards with risk heat maps
- Multi-criteria risk analysis (Financial, Operational, Compliance, Reputation)
- Predictive risk forecasting and trend analysis

### Sample Data & Testing URLs

#### Authentication & Access Control
- **Login**: `http://localhost:5000/login` 
- **Audit Logs**: `http://localhost:5000/audit/logs`
- **Admin Dashboard**: `http://localhost:5000/admin/dashboard`

#### Incident Management
- **Report Incident**: `http://localhost:5000/report_incident`
- **Incidents Dashboard**: `http://localhost:5000/incidents`
- **Sample Incidents**:
  - Incident #1: "Suspicious Network Activity Detected" (High severity)
  - Incident #2: "Potential Ransomware Infection" (Critical severity)

#### Risk Management
- **Risk Dashboard**: `http://localhost:5000/risk_dashboard`
- **Risks List**: `http://localhost:5000/risks`
- **Critical Risks**: `http://localhost:5000/critical_risks`

#### Threat Intelligence
- **IoC Analysis**: `http://localhost:5000/ioc_analysis`
  - Sample IoCs: malicious.example.com, 192.168.1.100, fake-bank-login.com
- **Malware Analysis**: `http://localhost:5000/malware_analysis`
  - Sample: SHA256 hash with 47/72 detection ratio
- **APT Campaigns**: `http://localhost:5000/apt_campaigns`
- **Phishing Templates**: `http://localhost:5000/phishing_templates`

#### Compliance & Monitoring
- **Compliance Dashboard**: `http://localhost:5000/compliance`
- **Monitoring**: `http://localhost:5000/monitoring`
- **Detection Rules**: `http://localhost:5000/detection_rules`

#### Forensics & Evidence
- **Digital Forensics**: `http://localhost:5000/forensics`
- **Evidence Files**: `http://localhost:5000/evidence/[filename]`
- **Asset Discovery**: `http://localhost:5000/asset_discovery`
- **Vulnerability Scanning**: `http://localhost:5000/vulnerability_scan`

## 🏗️ Architecture

### System Components
```
grcPortal/
├── app.py                 # Main Flask application
├── models.py             # SQLAlchemy database models
├── llm_scan.py           # AI-powered scanning engine
├── db.py                 # Database configuration
├── docs/                 # Comprehensive documentation
├── templates/            # Jinja2 HTML templates
├── static/               # CSS, JavaScript, images
├── migrations/           # Database migrations
├── uploads/              # Secure file storage
├── reports/              # Generated reports
├── evidence/             # Forensic evidence
└── logs/                 # Application logs
```

### Technology Stack

#### Backend
- **Framework**: Flask 3.0+ with application factory pattern
- **Database**: SQLite with SQLAlchemy 2.0+ ORM and Flask-Migrate
- **Authentication**: Werkzeug security with session management and Zero Trust
- **API**: RESTful endpoints with JSON responses
- **Task Scheduling**: APScheduler for automated background tasks
- **Monitoring**: psutil for system resource monitoring

#### Frontend
- **UI Framework**: Bootstrap 5 with responsive design
- **Templating**: Jinja2 with component architecture
- **JavaScript**: Vanilla JS with modern ES6+ features
- **Charts**: Bootstrap components with custom visualizations

#### AI & Integration
- **LLM**: OpenRouter API integration with GPT models for document analysis
- **Document Processing**: PyPDF2 for PDF text extraction
- **External APIs**: Webhook system for real-time notifications
- **Identity**: LDAP/Active Directory integration ready
- **SIEM**: Security event correlation and alerting

#### Security & Compliance
- **Encryption**: End-to-end data protection with secure file handling
- **Audit**: Comprehensive logging with structured events and audit trails
- **Compliance**: Multi-framework automated assessment (NIST, ISO, GDPR, PCI DSS, HIPAA, SOX)
- **Forensics**: Digital evidence with integrity hashing and chain of custody
- **Threat Intelligence**: IoC analysis and malware detection integration

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Git (for cloning)
- SQLite (included with Python)

### Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd grcPortal
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Initialize database**:
   ```bash
   flask db upgrade
   ```

6. **Run the application**:
   ```bash
   python app.py
   ```

7. **Access the application**:
   Open your browser to `http://localhost:5000`

## 📖 Usage Guide

### Core Workflows

#### 1. Risk Management
1. Navigate to Risk Management → Risk Register
2. Use various identification methods (Brainstorming, Checklists, SWOT)
3. Review AI-generated mitigation plans
4. Track approval workflows and monitoring

#### 2. Compliance Automation
1. Upload policy documents for AI analysis
2. Review automated compliance mapping
3. Monitor compliance scores across frameworks
4. Generate compliance reports

#### 3. Incident Response
1. Report incidents through the portal
2. Follow automated IRP workflows
3. Collect and manage digital evidence
4. Generate forensic reports

#### 4. Program Management
1. Create risk management programs
2. Implement framework-based phases
3. Conduct gap analysis
4. Monitor program effectiveness

## 🔧 Configuration

### Environment Variables
```bash
# Flask Configuration
FLASK_ENV=production
SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=sqlite:///instance/app.db

# AI Integration
OPENROUTER_API_KEY=your-openrouter-key
MODEL_NAME=openai/gpt-oss-20b:free

# Security
ALLOWED_IPS=127.0.0.1,192.168.1.0/24
SESSION_TIMEOUT_MINUTES=10

# External Integrations
LDAP_SERVER=ldap://your-ldap-server
SIEM_WEBHOOK_URL=https://your-siem-webhook
```

### Advanced Configuration
- **Database**: SQLite with SQLAlchemy ORM (production-ready with proper migrations)
- **Task Scheduling**: APScheduler for automated archiving and health monitoring
- **Monitoring**: Built-in security metrics collection and health checks
- **Logging**: Structured logging with audit trails and security event tracking
- **File Security**: Secure file upload handling with type validation and cleanup

## 🐳 Docker Deployment

### Development
```bash
docker build -t grc-portal .
docker run -p 5000:5000 grc-portal
```

### Production
```yaml
# docker-compose.yml
version: '3.8'
services:
  grc-portal:
    build: .
    ports:
      - "8000:8000"
    environment:
      - FLASK_ENV=production
    volumes:
      - ./instance:/app/instance
      - ./uploads:/app/uploads
      - ./logs:/app/logs
```

## 📊 API Documentation

### REST API Endpoints

#### Risk Management
```http
GET    /api/risks              # List risks with filtering
POST   /api/risks              # Create new risk
GET    /api/risks/{id}         # Get risk details
PUT    /api/risks/{id}         # Update risk
DELETE /api/risks/{id}         # Delete risk
```

#### Compliance
```http
GET    /api/compliance         # Compliance status
POST   /api/compliance/scan    # Trigger compliance scan
GET    /api/compliance/{id}    # Framework details
```

#### Webhooks
```http
POST   /webhook/risk-alert     # Risk threshold alerts
POST   /webhook/incident       # Incident notifications
POST   /webhook/compliance     # Compliance updates
```

## 🔒 Security

### Zero Trust Implementation
- **Identity Verification**: Continuous authentication validation
- **Device Trust**: IP-based access control and device fingerprinting
- **Network Security**: Micro-segmentation and secure API design
- **Data Protection**: End-to-end encryption and secure key management

### Compliance Certifications
- **NIST SP 800-53**: Complete control implementation
- **ISO 27001**: Information security management system
- **GDPR**: Data protection and privacy compliance
- **PCI DSS**: Payment card industry security standards

## 📈 Monitoring & Analytics

### Built-in Monitoring
- **Application Metrics**: Response times, error rates, throughput
- **Security Events**: Authentication attempts, access patterns, audit trails
- **Risk Metrics**: Risk score trends, compliance status, indicator monitoring
- **System Health**: CPU, memory, disk usage monitoring with automated health checks
- **Threat Intelligence**: IoC tracking, malware analysis, APT campaign monitoring
- **Compliance Monitoring**: Framework compliance scores, gap analysis, remediation tracking

### Dashboard Features
- **Executive Dashboard**: High-level risk and compliance overview with KPI tracking
- **Operational Dashboard**: Real-time monitoring and alerts with automated health checks
- **Compliance Dashboard**: Framework-specific compliance tracking with gap analysis
- **Security Dashboard**: Incident and forensic activity monitoring with threat intelligence
- **Risk Dashboard**: Multi-criteria risk assessment with heat maps and trend analysis
- **KPI Dashboard**: Leading and lagging indicators with automated reporting

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes with comprehensive tests
4. Run security scans: `bandit -r .`
5. Submit a pull request

### Code Standards
- **Python**: PEP 8 compliance with type hints and modern Python features
- **Security**: Input validation, secure coding practices, and Zero Trust principles
- **Testing**: Comprehensive unit and integration tests with security testing
- **Documentation**: Detailed docstrings, README updates, and inline comments
- **Database**: SQLAlchemy ORM with proper migrations and session management

## 📄 Documentation

### Documentation Structure
```
docs/
├── index.md                 # Comprehensive technical documentation
├── README.md               # Documentation overview
├── risk_framework.md       # Risk management framework details
├── incident_reporting_guide.md    # Incident response procedures
├── file_upload_procedure.md       # Secure file handling
├── gdpr_compliance_matrix.md     # GDPR compliance mapping
├── organizational_alignment_mapping.md  # Business alignment
└── playbooks.md            # Security playbooks and procedures
```

### Key Documentation Areas
- **Architecture**: System design and component relationships
- **Security**: Zero Trust implementation and compliance mappings
- **API Reference**: Complete endpoint documentation with examples
- **Deployment**: Production deployment and configuration
- **Operations**: Monitoring, backup, maintenance, and automated tasks
- **Risk Management**: Framework implementation and assessment methodologies
- **Threat Intelligence**: IoC analysis and malware detection procedures

## 🐛 Troubleshooting

### Common Issues

#### Application Won't Start
```bash
# Check Python version
python --version

# Verify dependencies
pip check

# Check database connectivity
python -c "from db import get_session; print('DB OK')"
```

#### AI Features Not Working
```bash
# Verify API key
echo $OPENROUTER_API_KEY

# Test API connectivity
curl -H "Authorization: Bearer $OPENROUTER_API_KEY" \
     https://openrouter.ai/api/v1/models
```

#### Permission Errors
```bash
# Fix directory permissions
sudo chown -R www-data:www-data /var/www/grc-portal
sudo chmod -R 755 /var/www/grc-portal
```

## 📞 Support

### Community Support
- **Issues**: GitHub Issues for bug reports and feature requests
- **Discussions**: GitHub Discussions for questions and community support
- **Documentation**: Comprehensive docs in the `docs/` directory

### Enterprise Support
- **Professional Services**: Custom implementation and integration
- **Training**: Risk management and compliance training programs
- **Consulting**: Security assessment and compliance gap analysis

## 📋 Roadmap

### Version 2.0 Features
- [ ] Multi-tenant architecture with organization isolation
- [ ] Advanced AI risk prediction with machine learning
- [ ] Real-time collaborative features and shared workspaces
- [ ] Mobile application for risk management on-the-go
- [ ] Advanced reporting and analytics with predictive insights

### Version 1.5 Enhancements (Current)
- [x] Enhanced SIEM integration with automated log correlation
- [x] Automated compliance remediation workflows
- [x] Advanced threat intelligence with IoC analysis
- [x] Performance optimization with background task processing
- [x] Comprehensive monitoring and health checks
- [x] Multi-framework compliance support (NIST, ISO, GDPR, PCI DSS, HIPAA, SOX)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **NIST RMF**: Risk Management Framework guidance
- **ISO Standards**: International standards for security and risk management
- **Open Source Community**: Flask, SQLAlchemy, and other open source projects
- **Security Researchers**: Continuous security research and best practices

---

**Built with ❤️ for enterprise security and compliance professionals**

*For detailed technical documentation, see [docs/index.md](docs/index.md)*

