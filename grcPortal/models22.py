"""
Database Models and Enums for GRC Portal

This module defines all SQLAlchemy database models, enumerations, and relationships
for the Governance, Risk, and Compliance (GRC) portal. It implements NIST RMF
(Risk Management Framework) concepts and provides structured data storage for
security assessments, compliance tracking, and incident management.

Core Components:
- Enums: Standardized values for compliance frameworks, risk levels, incident status
- Base Classes: SQLAlchemy declarative base and common model functionality
- Business Models: User, Risk, Compliance, Incident, Evidence, etc.
- Relationships: Foreign key relationships and back-references between models

Key Features:
- NIST RMF alignment with asset/threat/vulnerability/control structure
- Risk scoring calculations (likelihood × impact)
- Quantitative risk analysis (ALE, EMV calculations)
- Incident Response Plan (IRP) tracking
- Digital evidence collection with integrity hashing
- Multi-framework compliance support

Database Tables:
- users: User accounts and authentication
- uploads: File upload tracking
- scan_results: LLM analysis results
- risks: Risk assessments with NIST RMF structure
- compliance_scores: Framework compliance tracking
- dependencies: Software dependency risk analysis
- incidents: Security incident management
- evidence: Digital evidence collection
- malware_samples: Malware sample submissions
- malware_analyses: Malware analysis results
- phishing_templates: Phishing email templates
- apt_campaigns: APT campaign documentation
- attack_mappings: MITRE ATT&CK mappings
- vulnerability_scans: Vulnerability scan results
- vulnerability_findings: Individual vulnerability findings
- asset_discoveries: Asset discovery scan results
- discovered_services: Services found on assets

Security Considerations:
- Input validation through SQLAlchemy column constraints
- Relationship integrity through foreign key constraints
- Audit trails with automatic timestamps
- Secure password storage (handled in application layer)

Usage:
    from models import User, Risk, Incident
    # Models are used through SQLAlchemy sessions
"""

from typing import List
from datetime import datetime, timezone
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Boolean, DateTime, ForeignKey, Text, Float, Enum
from enum import Enum as PyEnum


def calculate_emv(probability: float, impact: float) -> float:
    """
    Calculate Expected Monetary Value (EMV).

    EMV = Probability × Impact

    Args:
        probability: Probability of occurrence (0-1)
        impact: Financial impact amount

    Returns:
        float: Expected monetary value
    """
    return probability * impact


def calculate_ale(probability: float, impact: float) -> float:
    """
    Calculate Annual Loss Expectancy (ALE).

    ALE = Probability × Impact

    Args:
        probability: Annual probability of occurrence (0-1)
        impact: Single loss expectancy (financial impact)

    Returns:
        float: Annual loss expectancy
    """
    return probability * impact


class ComplianceFramework(PyEnum):
    NIST_SP_800_53 = "NIST SP 800-53"
    NIST_CSF = "NIST CSF"
    ISO_27001 = "ISO 27001"
    ISO_27002 = "ISO 27002"
    PCI_DSS = "PCI DSS"
    HIPAA = "HIPAA"
    SOX = "SOX"
    GDPR = "GDPR"
    CIS_CONTROLS = "CIS Controls"
    COBIT = "COBIT"


class RiskSeverity(PyEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class IncidentStatus(PyEnum):
    OPEN = "open"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class IncidentSeverity(PyEnum):
    LOW = "Low"            # Minor issues, limited impact
    MEDIUM = "Medium"      # Moderate disruption, some business impact
    HIGH = "High"          # Significant concern, major business impact
    CRITICAL = "Critical"  # Severe breach, critical business impact


class EvidenceType(PyEnum):
    LOG = "log"
    SCREENSHOT = "screenshot"
    DOCUMENT = "document"
    OTHER = "other"


class RiskStatus(PyEnum):
    OPEN = "open"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    CLOSED = "closed"


class RiskCategory(PyEnum):
    ACCESS_CONTROL = "Access Control"
    INCIDENT_RESPONSE = "Incident Response"
    AUDIT_LOGGING = "Audit & Logging"
    CONFIGURATION = "Configuration Management"
    CRYPTOGRAPHY = "Cryptography"
    DATA_PROTECTION = "Data Protection"
    NETWORK_SECURITY = "Network Security"
    PHYSICAL_SECURITY = "Physical Security"
    PERSONNEL_SECURITY = "Personnel Security"
    SUPPLY_CHAIN = "Supply Chain"
    VULNERABILITY_MANAGEMENT = "Vulnerability Management"


class RiskTreatment(PyEnum):
    ACCEPT = "accept"
    MITIGATE = "mitigate"
    TRANSFER = "transfer"
    AVOID = "avoid"


class ApprovalStatus(PyEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"


class GovernanceRole(PyEnum):
    RISK_OWNER = "risk_owner"
    COMPLIANCE_OFFICER = "compliance_officer"
    AUDITOR = "auditor"
    BUSINESS_OWNER = "business_owner"
    IT_SECURITY = "it_security"


class NIST_RMF_Phase(PyEnum):
    PREPARE = "prepare"
    CATEGORIZE = "categorize"
    SELECT = "select"
    IMPLEMENT = "implement"
    ASSESS = "assess"
    AUTHORIZE = "authorize"
    MONITOR = "monitor"


class RiskCriteria(PyEnum):
    FINANCIAL = "Financial"
    OPERATIONAL = "Operational"
    COMPLIANCE = "Compliance"
    REPUTATION = "Reputation"


class BusinessImpactType(PyEnum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy database models.
    Provides common functionality and configuration for all database entities
    in the GRC portal. All models inherit from this base class to ensure
    consistent behavior and automatic timestamp management.
    Features:
        - Automatic table naming from class names
        - Declarative base for SQLAlchemy ORM
        - Foundation for relationship definitions
        - Consistent model structure across the application
    Note:
        This class should not be instantiated directly. Use specific model
        classes that inherit from Base for database operations.
    """
    pass


class User(Base):
    """
    User account model for authentication and authorization.

    Represents user accounts in the GRC portal with role-based access control,
    approval limits, and audit trail capabilities. Supports multi-level
    approval workflows and governance escalation procedures.

    Attributes:
        id: Primary key
        email: Unique email address for authentication
        password_hash: Securely hashed password
        is_verified: Account verification status
        role: User role (user, admin, auditor)
        approval_limit: Maximum approval amount for risk decisions
        escalation_threshold: Risk score threshold for escalation
        escalation_level: Current escalation level
        audit_trail_enabled: Whether audit logging is enabled
        created_at: Account creation timestamp
        updated_at: Last update timestamp
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    role: Mapped[str] = mapped_column(String(50), default="user")  # user, admin, auditor

    # Approval and escalation settings
    approval_limit: Mapped[float] = mapped_column(Float, default=10000.0)
    escalation_threshold: Mapped[int] = mapped_column(Integer, default=15)
    escalation_level: Mapped[str] = mapped_column(String(50), default="none")
    audit_trail_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    uploads = relationship("Upload", back_populates="user")
    risks = relationship("Risk", back_populates="owner_user")
    incidents = relationship("Incident", back_populates="reported_by_user")
    audit_logs = relationship("AuditLog", back_populates="user")


class Upload(Base):
    """
    File upload tracking model for document security scanning.

    Tracks uploaded files with user ownership, file metadata, and scan status.
    Supports secure file handling and automatic cleanup procedures.

    Attributes:
        id: Primary key
        user_id: Foreign key to user who uploaded the file
        filename: Original filename
        saved_path: Server path where file is stored
        file_size: Size of uploaded file in bytes
        mime_type: MIME type of the uploaded file
        upload_timestamp: When the file was uploaded
        scan_status: Current scan status (pending, scanning, completed, failed)
        is_deleted: Soft delete flag for cleanup
    """
    __tablename__ = "uploads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    saved_path: Mapped[str] = mapped_column(String(500), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=True)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=True)
    upload_timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    scan_status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, scanning, completed, failed
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    user = relationship("User", back_populates="uploads")
    scan_result = relationship("ScanResult", back_populates="upload", uselist=False)


class EthicalDecision(Base):
    """Represents ethical decision-making process and documentation."""
    __tablename__ = "ethical_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    scenario_type: Mapped[str] = mapped_column(String(100), nullable=False)  # data_privacy, security_tradeoff, vendor_risk, etc.

    # Ethical analysis
    ethical_principles_applied: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of principles
    stakeholder_impact_analysis: Mapped[str] = mapped_column(Text, nullable=True)  # JSON stakeholder analysis
    alternative_options: Mapped[str] = mapped_column(Text, nullable=True)  # JSON alternatives considered

    # Decision details
    decision_made: Mapped[str] = mapped_column(Text, nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    ethical_risk_level: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical

    # Implementation
    implementation_plan: Mapped[str] = mapped_column(Text, nullable=True)
    monitoring_requirements: Mapped[str] = mapped_column(Text, nullable=True)

    # Governance
    decided_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    decision_maker = relationship("User", foreign_keys=[decided_by])
    reviewer = relationship("User", foreign_keys=[reviewed_by])


class ComplianceObligation(Base):
    """Represents specific compliance obligations from regulatory requirements."""
    __tablename__ = "compliance_obligations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., "GDPR-25", "HIPAA-164.308"
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Obligation details
    category: Mapped[str] = mapped_column(String(100), nullable=True)  # Data Protection, Security, Financial, etc.
    mandatory: Mapped[bool] = mapped_column(Boolean, default=True)
    priority_level: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical

    # Assessment
    current_compliance_score: Mapped[float] = mapped_column(Float, default=0.0)
    target_score: Mapped[float] = mapped_column(Float, default=100.0)
    last_assessed: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    next_assessment_due: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Risk assessment
    risk_likelihood: Mapped[int] = mapped_column(Integer, default=3)  # 1-5 scale
    risk_impact: Mapped[int] = mapped_column(Integer, default=3)      # 1-5 scale
    risk_score: Mapped[int] = mapped_column(Integer, default=9)       # likelihood × impact

    # Control mapping
    control_mappings: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of NIST controls
    assessment_procedures: Mapped[str] = mapped_column(Text, nullable=True)  # JSON assessment steps
    evidence_requirements: Mapped[str] = mapped_column(Text, nullable=True)  # JSON evidence types

    # Remediation
    remediation_plan: Mapped[str] = mapped_column(Text, nullable=True)
    responsible_party: Mapped[str] = mapped_column(String(255), nullable=True)
    timeline_days: Mapped[int] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def calculate_risk_score(self):
        """Calculate compliance risk score."""
        self.risk_score = self.risk_likelihood * self.risk_impact
        return self.risk_score

    def get_compliance_status(self):
        """Get compliance status based on current score."""
        if self.current_compliance_score >= 95:
            return "compliant"
        elif self.current_compliance_score >= 80:
            return "mostly_compliant"
        elif self.current_compliance_score >= 60:
            return "partially_compliant"
        else:
            return "non_compliant"


class ComplianceRiskAssessment(Base):
    """Represents comprehensive compliance risk assessments."""
    __tablename__ = "compliance_risk_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=True)
    assessment_type: Mapped[str] = mapped_column(String(50), default="comprehensive")  # comprehensive, targeted, regulatory

    # Assessment framework
    methodology: Mapped[str] = mapped_column(String(100), default="NIST_SP_800_30")
    frameworks_assessed: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of frameworks

    # Risk identification
    risks_identified: Mapped[int] = mapped_column(Integer, default=0)
    critical_risks: Mapped[int] = mapped_column(Integer, default=0)
    high_risks: Mapped[int] = mapped_column(Integer, default=0)
    medium_risks: Mapped[int] = mapped_column(Integer, default=0)
    low_risks: Mapped[int] = mapped_column(Integer, default=0)

    # Assessment results
    overall_risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    compliance_score: Mapped[float] = mapped_column(Float, default=0.0)
    recommendations_count: Mapped[int] = mapped_column(Integer, default=0)

    # Assessment details
    findings_summary: Mapped[str] = mapped_column(Text, nullable=True)
    executive_summary: Mapped[str] = mapped_column(Text, nullable=True)
    detailed_findings: Mapped[str] = mapped_column(Text, nullable=True)  # JSON detailed results

    # Status and timeline
    status: Mapped[str] = mapped_column(String(50), default="planned")  # planned, in_progress, completed, reviewed
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    completion_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    review_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Governance
    lead_assessor: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    approved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    next_assessment_due: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    assessor = relationship("User", foreign_keys=[lead_assessor])
    approver = relationship("User", foreign_keys=[approved_by])


class ComplianceIncident(Base):
    """Represents compliance incidents with standardized documentation."""
    __tablename__ = "compliance_incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)  # Auto-generated unique ID
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)  # data_breach, privacy_violation, security_incident, etc.
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # critical, high, medium, low

    # Incident details
    description: Mapped[str] = mapped_column(Text, nullable=False)
    date_occurred: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    date_discovered: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    discovery_method: Mapped[str] = mapped_column(String(100), nullable=True)

    # Impact assessment
    affected_individuals: Mapped[int] = mapped_column(Integer, default=0)
    affected_systems: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array
    business_impact: Mapped[str] = mapped_column(String(20), default="low")  # minimal, low, moderate, high, critical
    financial_impact: Mapped[float] = mapped_column(Float, default=0.0)
    regulatory_impact: Mapped[str] = mapped_column(Text, nullable=True)

    # Classification and status
    status: Mapped[str] = mapped_column(String(50), default="identified")  # identified, investigating, contained, resolved, closed
    root_cause: Mapped[str] = mapped_column(Text, nullable=True)
    contributing_factors: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array

    # Response actions
    immediate_actions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array
    containment_actions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array
    remediation_actions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array

    # Regulatory notifications
    regulatory_notifications_required: Mapped[bool] = mapped_column(Boolean, default=False)
    notifications_sent: Mapped[str] = mapped_column(Text, nullable=True)  # JSON notification records
    notification_deadlines: Mapped[str] = mapped_column(Text, nullable=True)  # JSON deadline tracking

    # Investigation and follow-up
    investigation_findings: Mapped[str] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[str] = mapped_column(Text, nullable=True)
    preventive_measures: Mapped[str] = mapped_column(Text, nullable=True)  # JSON recommendations

    # Governance
    reported_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    assigned_to: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    # Evidence and documentation
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)
    documentation_complete: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    resolved_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    reporter = relationship("User", foreign_keys=[reported_by])
    assignee = relationship("User", foreign_keys=[assigned_to])
    reviewer = relationship("User", foreign_keys=[reviewed_by])

    def generate_incident_id(self):
        """Generate unique incident ID."""
        timestamp = datetime.now().strftime("%Y%m%d")
        self.incident_id = f"CI-{timestamp}-{self.id:04d}"
        return self.incident_id

    def calculate_severity_score(self):
        """Calculate severity score based on impact factors."""
        severity_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        impact_scores = {"minimal": 1, "low": 2, "moderate": 3, "high": 4, "critical": 5}

        severity_num = severity_scores.get(self.severity, 2)
        impact_num = impact_scores.get(self.business_impact, 2)
        individuals_factor = min(self.affected_individuals / 100, 5) if self.affected_individuals else 0

        return (severity_num + impact_num + individuals_factor) / 3

    def get_response_timeline(self):
        """Get required response timeline based on severity."""
        timelines = {
            "critical": "Immediate (within 1 hour)",
            "high": "Within 24 hours",
            "medium": "Within 1 week",
            "low": "Within 1 month"
        }
        return timelines.get(self.severity, "Within 1 week")