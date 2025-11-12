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


class ComplianceWorkflow(Base):
    """Automated compliance workflow system with multi-stage decision points."""

    __tablename__ = "compliance_workflows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Workflow configuration
    workflow_type: Mapped[str] = mapped_column(String(50), nullable=False)  # assessment, remediation, monitoring, reporting
    trigger_type: Mapped[str] = mapped_column(String(50), nullable=False)  # scheduled, event_based, manual, api_triggered

    # Framework and scope
    framework: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=True)  # JSON scope definition
    target_systems: Mapped[str] = mapped_column(Text, nullable=True)  # JSON target systems

    # Workflow stages (JSON)
    stages: Mapped[str] = mapped_column(Text, nullable=False)  # JSON workflow stages with decision points
    decision_points: Mapped[str] = mapped_column(Text, nullable=True)  # JSON decision logic

    # Automation settings
    ai_integration_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_approval_threshold: Mapped[float] = mapped_column(Float, default=0.0)  # Auto-approve below this score
    escalation_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Exception handling
    exception_handling_rules: Mapped[str] = mapped_column(Text, nullable=True)  # JSON exception rules
    fallback_procedures: Mapped[str] = mapped_column(Text, nullable=True)  # JSON fallback procedures

    # Status and execution
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft, active, paused, completed, error
    last_execution: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    next_scheduled_run: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Performance metrics
    success_rate: Mapped[float] = mapped_column(Float, default=0.0)
    average_execution_time: Mapped[int] = mapped_column(Integer, default=0)  # seconds
    total_executions: Mapped[int] = mapped_column(Integer, default=0)

    # Governance
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    approved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    approver = relationship("User", foreign_keys=[approved_by])
    executions = relationship("WorkflowExecution", back_populates="workflow", cascade="all, delete-orphan")


class WorkflowExecution(Base):
    """Individual execution instance of a compliance workflow."""

    __tablename__ = "workflow_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workflow_id: Mapped[int] = mapped_column(ForeignKey("compliance_workflows.id"), nullable=False)

    # Execution details
    execution_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)  # UUID-style identifier
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, running, completed, failed, paused

    # Progress tracking
    current_stage: Mapped[str] = mapped_column(String(100), nullable=True)
    progress_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    stage_results: Mapped[str] = mapped_column(Text, nullable=True)  # JSON results by stage

    # Decision outcomes
    decisions_made: Mapped[str] = mapped_column(Text, nullable=True)  # JSON decision history
    ai_decisions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON AI-driven decisions

    # Exception handling
    exceptions_encountered: Mapped[str] = mapped_column(Text, nullable=True)  # JSON exceptions
    escalations_triggered: Mapped[str] = mapped_column(Text, nullable=True)  # JSON escalations

    # Results and metrics
    final_result: Mapped[str] = mapped_column(Text, nullable=True)  # JSON final outcome
    compliance_score: Mapped[float] = mapped_column(Float, nullable=True)
    execution_time_seconds: Mapped[int] = mapped_column(Integer, nullable=True)

    # Error handling
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)

    # Timestamps
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    workflow = relationship("ComplianceWorkflow", back_populates="executions")


class WorkflowException(Base):
    """Exception handling and escalation tracking for compliance workflows."""

    __tablename__ = "workflow_exceptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    execution_id: Mapped[int] = mapped_column(ForeignKey("workflow_executions.id"), nullable=False)

    # Exception details
    exception_type: Mapped[str] = mapped_column(String(100), nullable=False)  # system_error, validation_error, timeout, etc.
    severity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Context
    stage_name: Mapped[str] = mapped_column(String(100), nullable=True)
    error_code: Mapped[str] = mapped_column(String(50), nullable=True)
    error_details: Mapped[str] = mapped_column(Text, nullable=True)  # JSON error context

    # Resolution
    resolution_strategy: Mapped[str] = mapped_column(String(100), nullable=True)  # auto_retry, manual_intervention, skip_stage, escalate
    resolution_notes: Mapped[str] = mapped_column(Text, nullable=True)
    resolved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Escalation
    escalation_required: Mapped[bool] = mapped_column(Boolean, default=False)
    escalation_level: Mapped[str] = mapped_column(String(50), nullable=True)  # team_lead, management, executive
    escalation_reason: Mapped[str] = mapped_column(Text, nullable=True)
    escalated_to: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    escalation_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Status
    status: Mapped[str] = mapped_column(String(50), default="open")  # open, resolved, escalated, closed

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    execution = relationship("WorkflowExecution", backref="exceptions")
    resolver = relationship("User", foreign_keys=[resolved_by])
    escalator = relationship("User", foreign_keys=[escalated_to])


class ComplianceROI(Base):
    """ROI analysis and cost-benefit calculations for compliance automation."""

    __tablename__ = "compliance_roi"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_name: Mapped[str] = mapped_column(String(255), nullable=False)
    analysis_type: Mapped[str] = mapped_column(String(50), nullable=False)  # workflow_automation, control_implementation, technology_investment

    # Time period
    analysis_period_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    analysis_period_end: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Cost components (JSON)
    implementation_costs: Mapped[str] = mapped_column(Text, nullable=True)  # JSON breakdown of implementation costs
    operational_costs: Mapped[str] = mapped_column(Text, nullable=True)  # JSON ongoing operational costs
    maintenance_costs: Mapped[str] = mapped_column(Text, nullable=True)  # JSON maintenance costs

    # Benefit components (JSON)
    time_savings: Mapped[str] = mapped_column(Text, nullable=True)  # JSON time savings by activity
    error_reduction: Mapped[str] = mapped_column(Text, nullable=True)  # JSON error reduction metrics
    compliance_improvements: Mapped[str] = mapped_column(Text, nullable=True)  # JSON compliance score improvements

    # Financial calculations
    total_investment: Mapped[float] = mapped_column(Float, default=0.0)
    annual_savings: Mapped[float] = mapped_column(Float, default=0.0)
    net_present_value: Mapped[float] = mapped_column(Float, default=0.0)
    roi_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    payback_period_months: Mapped[float] = mapped_column(Float, default=0.0)

    # Risk reduction metrics
    risk_reduction_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    avoided_incidents_value: Mapped[float] = mapped_column(Float, default=0.0)
    compliance_fines_avoided: Mapped[float] = mapped_column(Float, default=0.0)

    # Qualitative benefits
    qualitative_benefits: Mapped[str] = mapped_column(Text, nullable=True)  # JSON qualitative benefits

    # Assumptions and methodology
    assumptions: Mapped[str] = mapped_column(Text, nullable=True)
    calculation_methodology: Mapped[str] = mapped_column(Text, nullable=True)

    # Status and approval
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft, reviewed, approved
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    reviewer = relationship("User", foreign_keys=[reviewed_by])
    approver = relationship("User", foreign_keys=[approved_by])

    def calculate_roi(self):
        """Calculate ROI metrics based on costs and benefits."""
        if self.total_investment > 0 and self.annual_savings > 0:
            # Simple ROI calculation
            self.roi_percentage = (self.annual_savings / self.total_investment) * 100

            # Payback period in months
            if self.annual_savings > 0:
                self.payback_period_months = (self.total_investment / self.annual_savings) * 12

        return self.roi_percentage, self.payback_period_months

    def calculate_npv(self, discount_rate: float = 0.1):
        """Calculate Net Present Value using discounted cash flow."""
        if not self.annual_savings or not self.total_investment:
            return 0.0

        # Simple NPV calculation (could be enhanced with detailed cash flows)
        years = 5  # Assume 5-year analysis period
        npv = -self.total_investment

        for year in range(1, years + 1):
            npv += self.annual_savings / ((1 + discount_rate) ** year)

        self.net_present_value = npv
        return npv


class WorkflowDecisionPoint(Base):
    """Decision points within compliance workflows with AI integration."""

    __tablename__ = "workflow_decision_points"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    workflow_id: Mapped[int] = mapped_column(ForeignKey("compliance_workflows.id"), nullable=False)

    # Decision point details
    decision_name: Mapped[str] = mapped_column(String(255), nullable=False)
    stage_name: Mapped[str] = mapped_column(String(100), nullable=False)
    decision_type: Mapped[str] = mapped_column(String(50), nullable=False)  # approval, routing, conditional, ai_driven

    # Decision logic
    conditions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON conditions for decision
    ai_prompt: Mapped[str] = mapped_column(Text, nullable=True)  # AI prompt for decision making
    ai_model: Mapped[str] = mapped_column(String(100), nullable=True)  # AI model to use

    # Decision outcomes
    possible_outcomes: Mapped[str] = mapped_column(Text, nullable=True)  # JSON possible outcomes
    default_outcome: Mapped[str] = mapped_column(String(100), nullable=True)

    # Automation settings
    auto_decision_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    auto_decision_threshold: Mapped[float] = mapped_column(Float, default=0.8)  # Confidence threshold for auto-decision

    # Escalation rules
    escalation_conditions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON escalation triggers
    escalation_levels: Mapped[str] = mapped_column(Text, nullable=True)  # JSON escalation levels

    # Performance tracking
    total_decisions: Mapped[int] = mapped_column(Integer, default=0)
    auto_decisions: Mapped[int] = mapped_column(Integer, default=0)
    manual_decisions: Mapped[int] = mapped_column(Integer, default=0)
    escalated_decisions: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    workflow = relationship("ComplianceWorkflow", backref="decision_points")


class User(Base):
    """
    Represents a user in the system with governance roles and responsibilities.

    Governance Roles and Responsibilities:

    Administrator Role ("admin"):
    - User account management and system configuration
    - Security policy enforcement and updates
    - System maintenance and configuration
    - Access to all system functions
    - Role assignment and permission management
    - System-wide audit log access
    - Incident response coordination

    Auditor Role ("auditor"):
    - Review system logs and security events
    - Monitor compliance with policies and standards
    - Validate security controls effectiveness
    - Generate audit reports and findings
    - Access to all incident and evidence data
    - Compliance monitoring and reporting
    - Security assessment and validation

    User Role ("user"):
    - Access to basic system functions
    - Report security incidents
    - View personal data and assessments
    - Upload files for security scanning
    - Comply with security policies
    - Access to personal incident reports
    - View assigned risk assessments
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    role: Mapped[str] = mapped_column(String(50), default="user")  # user, admin, auditor
    governance_role: Mapped[GovernanceRole] = mapped_column(Enum(GovernanceRole), nullable=True)
    department: Mapped[str] = mapped_column(String(100), nullable=True)
    approval_limit: Mapped[float] = mapped_column(Float, default=0.0)  # Maximum risk value user can approve
    escalation_threshold: Mapped[int] = mapped_column(Integer, default=15)  # Risk score threshold for escalation
    escalation_level: Mapped[str] = mapped_column(String(50), default="business_unit")  # business_unit, department, executive
    audit_trail_enabled: Mapped[bool] = mapped_column(Boolean, default=True)  # Enable audit logging for this user

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    uploads: Mapped[list["Upload"]] = relationship("Upload", back_populates="user")
    incidents: Mapped[list["Incident"]] = relationship("Incident", back_populates="reporter")
    evidence: Mapped[list["Evidence"]] = relationship("Evidence", back_populates="collector")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="user")


class Upload(Base):
    """
    Represents a file uploaded by a user for security scanning and analysis.

    Tracks uploaded files, their metadata, and relationships to scan results.
    Provides secure file handling with automatic cleanup and access control.
    Supports multiple file types (PDF, TXT) for GRC document analysis.

    Attributes:
        user_id: Foreign key to the user who uploaded the file
        filename: Original filename provided by user
        saved_path: Secure server path where file is stored
        uploaded_at: Timestamp of upload

    Relationships:
        user: Reference to User who uploaded the file
        scan_result: Associated security scan results (one-to-one)

    Security Features:
        - Filename sanitization to prevent path traversal
        - File type validation (PDF/TXT only)
        - Automatic cleanup after processing
        - User-specific access control

    Usage:
        Uploads are created when users submit files through the web interface.
        Files are automatically scanned and results linked back to the upload.
    """
    __tablename__ = "uploads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    saved_path: Mapped[str] = mapped_column(String(512), nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc))

    user: Mapped["User"] = relationship("User", back_populates="uploads")
    scan_result: Mapped["ScanResult"] = relationship("ScanResult", back_populates="upload", uselist=False)


class ScanResult(Base):
    """
    Represents the results of a comprehensive security scan on an uploaded file.

    Stores LLM-generated analysis results including compliance hits, risk assessments,
    and security findings. Provides structured storage for complex analysis data
    using JSON serialization for flexible content storage.

    Attributes:
        upload_id: Foreign key to the scanned upload
        summary: High-level summary of scan findings
        compliance_hits_json: JSON string of compliance framework matches
        risks_json: JSON string of identified risks
        scanned_at: Timestamp when scan was completed

    Relationships:
        upload: Reference to the scanned Upload
        risks: Collection of Risk objects created from scan results

    Data Storage:
        Uses JSON text fields to store complex structured data
        Supports multiple compliance frameworks simultaneously
        Enables detailed risk extraction and categorization

    Usage:
        Created automatically after file upload processing
        Used to generate risk assessments and compliance reports
        Provides audit trail for security analysis activities
    """
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id"), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=True)
    compliance_hits_json: Mapped[str] = mapped_column(Text, nullable=True)   # JSON as text
    risks_json: Mapped[str] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc))

    upload: Mapped["Upload"] = relationship("Upload", back_populates="scan_result")
    risks = relationship("Risk", back_populates="scan_result")


class Risk(Base):
    """Represents a comprehensive risk assessment in the system following NIST RMF and ISO 31000."""
    __tablename__ = "risks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset: Mapped[str] = mapped_column(String(500), nullable=False)  # NIST RMF: Information or system resource
    threat: Mapped[str] = mapped_column(String(500), nullable=False)  # NIST RMF: Potential for violation of security
    vulnerability: Mapped[str] = mapped_column(String(500), nullable=False)  # NIST RMF: Weakness that can be exploited
    control: Mapped[str] = mapped_column(String(500), nullable=False)  # NIST RMF: Safeguard/countermeasure
    compliance_standard: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=True)
    status: Mapped[RiskStatus] = mapped_column(Enum(RiskStatus), default=RiskStatus.OPEN)
    category: Mapped[RiskCategory] = mapped_column(Enum(RiskCategory), nullable=True)

    likelihood: Mapped[int] = mapped_column(Integer, default=1)  # 1–5 scale
    impact: Mapped[int] = mapped_column(Integer, default=1)      # 1–5 scale
    score: Mapped[int] = mapped_column(Integer, default=0)       # likelihood × impact

    # Security classification for Bell-LaPadula enforcement
    severity: Mapped[RiskSeverity] = mapped_column(Enum(RiskSeverity), default=RiskSeverity.MEDIUM)

    ale: Mapped[float] = mapped_column(Float, default=0.0)         # Annualized Loss Expectancy
    emv: Mapped[float] = mapped_column(Float, default=0.0)         # Expected Monetary Value

    mitigation_plan: Mapped[str] = mapped_column(Text, nullable=True)
    residual_risk: Mapped[str] = mapped_column(Text, nullable=True)
    owner: Mapped[str] = mapped_column(String(255), nullable=True)

    # Enhanced NIST RMF fields
    treatment: Mapped[RiskTreatment] = mapped_column(Enum(RiskTreatment), nullable=True)
    rmf_phase: Mapped[NIST_RMF_Phase] = mapped_column(Enum(NIST_RMF_Phase), default=NIST_RMF_Phase.PREPARE)
    approval_status: Mapped[ApprovalStatus] = mapped_column(Enum(ApprovalStatus), default=ApprovalStatus.PENDING)
    approver_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    # Risk quantification
    asset_value: Mapped[float] = mapped_column(Float, default=0.0)  # Asset value for ALE calculation
    mitigation_cost: Mapped[float] = mapped_column(Float, default=0.0)  # Cost of mitigation measures

    # Governance tracking
    business_impact: Mapped[str] = mapped_column(Text, nullable=True)
    regulatory_impact: Mapped[str] = mapped_column(Text, nullable=True)
    risk_appetite_level: Mapped[int] = mapped_column(Integer, default=3)  # 1-5 scale for organizational risk appetite

    # Additional NIST RMF fields for residual risk scoring
    residual_likelihood: Mapped[int] = mapped_column(Integer, default=1)  # Residual likelihood after mitigation
    residual_impact: Mapped[int] = mapped_column(Integer, default=1)      # Residual impact after mitigation
    residual_score: Mapped[int] = mapped_column(Integer, default=0)       # Calculated residual risk score

    # Escalation and approval workflow
    escalation_level: Mapped[str] = mapped_column(String(50), default="business_unit")  # business_unit, department, executive
    escalated_to: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    escalation_reason: Mapped[str] = mapped_column(Text, nullable=True)
    escalation_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Risk appetite and tolerance
    risk_tolerance_threshold: Mapped[int] = mapped_column(Integer, default=15)  # Risk score threshold for escalation
    risk_appetite_alignment: Mapped[str] = mapped_column(Text, nullable=True)  # How risk aligns with organizational appetite

    # Audit trail
    last_reviewed: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    next_review_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    review_frequency_days: Mapped[int] = mapped_column(Integer, default=90)  # Days between reviews

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    compliance = relationship("Compliance", back_populates="risk")
    scan_result_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_results.id"), nullable=True)
    scan_result = relationship("ScanResult", back_populates="risks")
    approver = relationship("User", foreign_keys=[approver_id])
    escalated_user = relationship("User", foreign_keys=[escalated_to])

    # Multi-criteria risk scoring
    financial_impact: Mapped[int] = mapped_column(Integer, nullable=False, default=1)  # 1-5 scale
    operational_impact: Mapped[int] = mapped_column(Integer, nullable=False, default=1)  # 1-5 scale
    compliance_impact: Mapped[int] = mapped_column(Integer, nullable=False, default=1)  # 1-5 scale
    reputation_impact: Mapped[int] = mapped_column(Integer, nullable=False, default=1)  # 1-5 scale

    # Weights for criteria (default equal weighting)
    financial_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)
    operational_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)
    compliance_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)
    reputation_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)

    # Business Impact Analysis
    rto_hours: Mapped[float] = mapped_column(Float, nullable=True)  # Recovery Time Objective in hours
    rpo_hours: Mapped[float] = mapped_column(Float, nullable=True)  # Recovery Point Objective in hours
    mtd_hours: Mapped[float] = mapped_column(Float, nullable=True)  # Maximum Tolerable Downtime in hours
    financial_impact_amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)  # Financial impact in currency
    dependency_mapping: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string of dependencies

    # Quantitative Risk Analysis
    annual_occurrence_probability: Mapped[float] = mapped_column(Float, nullable=True)  # Probability of occurrence per year (0-1)
    ale_calculated: Mapped[float] = mapped_column(Float, nullable=True)  # Calculated Annual Loss Expectancy
    emv_calculated: Mapped[float] = mapped_column(Float, nullable=True)  # Calculated Expected Monetary Value

    # Evaluation criteria documentation
    evaluation_criteria: Mapped[str] = mapped_column(Text, nullable=True)  # Documented evaluation criteria
    stakeholder_approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    stakeholder_approval_notes: Mapped[str] = mapped_column(Text, nullable=True)

    # Store JSON response for Risk Mitigation Planning
    mitigation_plan_json: Mapped[str] = mapped_column(Text, nullable=True)  # Store JSON response
    mitigation_plan_updated: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Traceability foreign key to source tables
    source_table: Mapped[str] = mapped_column(String(255), nullable=True)  # e.g., 'vulnerability_findings', 'incidents'
    source_id: Mapped[int] = mapped_column(Integer, nullable=True)  # Primary key ID of the source record


    def calculate_score(self, use_multi_criteria=False):
        """
        Calculate the overall risk score using traditional or multi-criteria methods.

        Supports two calculation approaches:
        1. Traditional: likelihood × impact (1-25 scale)
        2. Multi-criteria: Weighted combination of financial, operational, compliance, reputation impacts

        Args:
            use_multi_criteria (bool): If True, uses weighted multi-criteria calculation.
                                      If False, uses traditional likelihood × impact.

        Returns:
            int: Calculated risk score (1-25 scale)

        Side Effects:
            Updates self.score attribute
            Auto-determines severity based on score ranges
            Sets appropriate RiskSeverity enum value

        Scoring Ranges:
            1-5: Low severity
            6-11: Medium severity
            12-19: High severity
            20-25: Critical severity

        Note:
            Multi-criteria scoring provides more nuanced risk assessment
            Traditional scoring maintains backward compatibility
        """
        if use_multi_criteria:
            return self.calculate_multi_criteria_score()
        else:
            # Original logic
            self.score = self.likelihood * self.impact
            # Auto-determine severity based on score
            if self.score >= 20:
                self.severity = RiskSeverity.CRITICAL
            elif self.score >= 12:
                self.severity = RiskSeverity.HIGH
            elif self.score >= 6:
                self.severity = RiskSeverity.MEDIUM
            else:
                self.severity = RiskSeverity.LOW
            return self.score

    def calculate_ale(self, asset_value: float = 100000.0):
        """
        Calculate Annualized Loss Expectancy (ALE) for quantitative risk analysis.

        ALE represents the expected annual financial loss from a risk occurrence.
        Formula: ALE = (Likelihood/5) × (Impact/5) × Asset_Value

        Args:
            asset_value (float): Value of the asset at risk (default: $100,000)

        Side Effects:
            Updates self.ale attribute with calculated value

        Note:
            Uses normalized likelihood and impact scales (1-5)
            Assumes asset_value is the single loss expectancy (SLE)
            Provides quantitative basis for risk prioritization
        """
        self.ale = (self.likelihood / 5.0) * (self.impact / 5.0) * asset_value

    def calculate_emv(self, mitigation_cost: float = 0.0):
        """
        Calculate Expected Monetary Value (EMV) considering mitigation costs.

        EMV represents the net expected value after accounting for mitigation expenses.
        Formula: EMV = ALE - Mitigation_Cost

        Args:
            mitigation_cost (float): Cost of implementing risk mitigation measures

        Side Effects:
            Updates self.emv attribute with calculated net value

        Note:
            Positive EMV indicates mitigation costs exceed expected losses
            Negative EMV indicates cost-effective mitigation
            Used for cost-benefit analysis of risk treatments
        """
        self.emv = self.ale - mitigation_cost

    def calculate_quantitative_metrics(self):
        """Calculate EMV and ALE using quantitative risk analysis"""
        if self.financial_impact_amount and self.annual_occurrence_probability:
            self.emv_calculated = calculate_emv(
                self.annual_occurrence_probability,
                self.financial_impact_amount
            )
            self.ale_calculated = calculate_ale(
                self.annual_occurrence_probability,
                self.financial_impact_amount
            )

    def calculate_residual_score(self):
        """Calculate residual risk score after mitigation"""
        self.residual_score = self.residual_likelihood * self.residual_impact
        # Auto-determine residual severity based on score
        if self.residual_score >= 20:
            self.severity = RiskSeverity.CRITICAL
        elif self.residual_score >= 12:
            self.severity = RiskSeverity.HIGH
        elif self.residual_score >= 6:
            self.severity = RiskSeverity.MEDIUM
        else:
            self.severity = RiskSeverity.LOW

    def should_escalate(self):
        """
        Determine if the risk requires escalation based on severity thresholds.

        Evaluates risk against organizational tolerance levels and impact criteria
        to determine if higher-level approval or attention is required.

        Returns:
            bool: True if risk should be escalated, False otherwise

        Escalation Criteria:
            - Risk score exceeds tolerance threshold (default: 15)
            - High financial impact (≥4) or operational impact (≥4)
            - Critical severity classification

        Note:
            Used by approval workflow to route risks appropriately
            Supports governance escalation procedures
            Configurable through risk_tolerance_threshold attribute
        """
        if self.score >= self.risk_tolerance_threshold:
            return True
        if self.financial_impact >= 4 or self.operational_impact >= 4:
            return True
        return False


    def get_escalation_level(self):
        """
        Determine the appropriate escalation level based on risk score severity.

        Maps risk scores to organizational escalation hierarchy levels for
        appropriate governance routing and approval authority assignment.

        Returns:
            str: Escalation level ("executive", "department", "business_unit", "none")

        Escalation Levels:
            - executive: Risk score ≥21 (Critical risks)
            - department: Risk score 13-20 (High risks)
            - business_unit: Risk score 6-12 (Medium risks)
            - none: Risk score 1-5 (Low risks)

        Note:
            Used by approval workflow to determine required approval authority
            Supports hierarchical governance structures
            Configurable escalation thresholds
        """
        if self.score >= 21:  # Critical
            return "executive"
        elif self.score >= 13:  # High
            return "department"
        elif self.score >= 6:  # Medium
            return "business_unit"
        else:  # Low
            return "none"

    def update_next_review_date(self):
        """
        Update the next scheduled review date based on risk severity and frequency settings.

        Calculates review intervals based on risk criticality to ensure appropriate
        monitoring frequency. Critical risks are reviewed more frequently than low risks.

        Side Effects:
            Updates self.next_review_date attribute with calculated future date

        Review Intervals:
            - Critical severity: Minimum 30 days (or custom frequency if shorter)
            - High severity: Minimum 60 days (or custom frequency if shorter)
            - Medium/Low severity: Uses review_frequency_days setting

        Note:
            Ensures minimum review frequencies for high-risk items
            Uses datetime.timedelta for date calculations
            Supports configurable review frequencies per risk
        """
        from datetime import timedelta
        if self.severity == RiskSeverity.CRITICAL:
            days = min(self.review_frequency_days, 30)  # Max 30 days for critical risks
        elif self.severity == RiskSeverity.HIGH:
            days = min(self.review_frequency_days, 60)  # Max 60 days for high risks
        else:
            days = self.review_frequency_days

        self.next_review_date = datetime.now(timezone.utc) + timedelta(days=days)

    def calculate_multi_criteria_score(self):
        """
        Calculate risk score using weighted multi-criteria evaluation approach.

        Applies weighted scoring across financial, operational, compliance, and
        reputation impact dimensions. Provides more nuanced risk assessment than
        traditional likelihood × impact calculation.

        Returns:
            int: Weighted risk score (1-25 scale)

        Calculation Process:
            1. Normalize each impact criterion to 0-1 scale
            2. Apply dimension-specific weights
            3. Sum weighted scores
            4. Convert to 1-25 scale for consistency

        Weight Configuration:
            - Financial: 25% (configurable via financial_weight)
            - Operational: 25% (configurable via operational_weight)
            - Compliance: 25% (configurable via compliance_weight)
            - Reputation: 25% (configurable via reputation_weight)

        Note:
            Supports customized weighting for different organizational priorities
            Maintains compatibility with existing scoring system
            Enables more sophisticated risk prioritization
        """
        # Normalize each criterion to 0-1 scale
        normalized_financial = (self.financial_impact - 1) / 4.0
        normalized_operational = (self.operational_impact - 1) / 4.0
        normalized_compliance = (self.compliance_impact - 1) / 4.0
        normalized_reputation = (self.reputation_impact - 1) / 4.0

        # Calculate weighted score
        weighted_score = (
            normalized_financial * self.financial_weight +
            normalized_operational * self.operational_weight +
            normalized_compliance * self.compliance_weight +
            normalized_reputation * self.reputation_weight
            )

        # Convert to 1-25 scale for consistency with existing scoring
        self.score = int(weighted_score * 25) + 1
        return self.score

    def calculate_business_impact_score(self):
        """Calculate business impact score based on RTO, RPO, MTD."""
        if not all([self.rto_hours, self.rpo_hours, self.mtd_hours]):
            return 0

        # Normalize to 1-5 scale
        rto_impact = min(self.rto_hours / 24, 5)  # Days to scale
        rpo_impact = min(self.rpo_hours / 24, 5)
        mtd_impact = min(self.mtd_hours / 24, 5)

        # Factor in financial impact
        financial_factor = min(self.financial_impact_amount / (self.asset_value or 100000), 5)

        return (rto_impact + rpo_impact + mtd_impact) / 3 + financial_factor / 2

    def get_dependency_graph(self):
        """Parse dependency mapping JSON."""
        import json
        try:
            return json.loads(self.dependency_mapping or '{}')
        except json.JSONDecodeError:
            return {}

    def validate_evaluation_criteria(self):
        """Validate that evaluation criteria are properly documented."""
        return bool(self.evaluation_criteria and len(self.evaluation_criteria.strip()) > 50)

    def get_stakeholder_approval_status(self):
        """Get formatted approval status."""
        if not self.stakeholder_approval_required:
            return "Not Required"
        elif self.approval_status == ApprovalStatus.APPROVED:
            return f"Approved - {self.stakeholder_approval_notes or 'No notes'}"
        elif self.approval_status == ApprovalStatus.REJECTED:
            return f"Rejected - {self.stakeholder_approval_notes or 'No notes'}"
        else:
            return f"Pending - {self.approval_status.value}"

    def get_impact_description(self, impact_type, level):
        """Get human-readable description for impact level (1-5 scale)"""
        descriptions = {
            1: "Minimal impact - Negligible effect on operations",
            2: "Low impact - Minor disruption, easily manageable",
            3: "Moderate impact - Noticeable effect requiring attention",
            4: "High impact - Significant disruption to operations",
            5: "Critical impact - Severe disruption, potential business failure"
        }
        return descriptions.get(level, f"Unknown impact level {level}")


class RiskManagementFramework(Base):
    """Risk management framework selection and customization"""
    __tablename__ = "risk_management_frameworks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)  # NIST RMF, ISO 31000, COSO
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    customization_notes: Mapped[str] = mapped_column(Text, nullable=True)
