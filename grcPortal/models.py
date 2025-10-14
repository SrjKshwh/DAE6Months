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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class RiskProgramPlan(Base):
    """Complete risk management program plan"""
    __tablename__ = "risk_program_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    framework_id: Mapped[int] = mapped_column(Integer, ForeignKey("risk_management_frameworks.id"))
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft, active, completed
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    total_budget: Mapped[float] = mapped_column(Float, default=0.0)
    created_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))

    # Program phases
    planning_phase_complete: Mapped[bool] = mapped_column(Boolean, default=False)
    implementation_phase_complete: Mapped[bool] = mapped_column(Boolean, default=False)
    monitoring_phase_complete: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    framework: Mapped[RiskManagementFramework] = relationship("RiskManagementFramework")
    creator: Mapped[User] = relationship("User")


class ProgramPhase(Base):
    """Program implementation phases with timelines and resources"""
    __tablename__ = "program_phases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(Integer, ForeignKey("risk_program_plans.id"))
    phase_name: Mapped[str] = mapped_column(String(100), nullable=False)
    phase_order: Mapped[int] = mapped_column(Integer, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    budget_allocated: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, in_progress, completed

    # Resource allocation
    personnel_required: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string
    tools_required: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string
    training_required: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    program: Mapped[RiskProgramPlan] = relationship("RiskProgramPlan", back_populates="phases")


# Add to RiskProgramPlan
RiskProgramPlan.phases: Mapped[List[ProgramPhase]] = relationship("ProgramPhase", back_populates="program", cascade="all, delete-orphan")


class GapAnalysis(Base):
    """Gap analysis for framework implementation"""
    __tablename__ = "gap_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(Integer, ForeignKey("risk_program_plans.id"))
    requirement_category: Mapped[str] = mapped_column(String(100), nullable=False)
    current_state: Mapped[str] = mapped_column(Text, nullable=True)
    required_state: Mapped[str] = mapped_column(Text, nullable=True)
    gap_description: Mapped[str] = mapped_column(Text, nullable=True)
    gap_severity: Mapped[str] = mapped_column(String(50), default="medium")  # low, medium, high, critical
    mitigation_plan: Mapped[str] = mapped_column(Text, nullable=True)
    estimated_cost: Mapped[float] = mapped_column(Float, default=0.0)
    timeline_months: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(50), default="open")  # open, in_progress, closed

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    program: Mapped[RiskProgramPlan] = relationship("RiskProgramPlan")


class RiskIndicator(Base):
    """Automated risk indicators for continuous monitoring"""
    __tablename__ = "risk_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False)  # leading, lagging
    data_source: Mapped[str] = mapped_column(String(200), nullable=False)
    calculation_method: Mapped[str] = mapped_column(Text, nullable=True)
    target_value: Mapped[float] = mapped_column(Float, nullable=True)
    threshold_warning: Mapped[float] = mapped_column(Float, nullable=True)
    threshold_critical: Mapped[float] = mapped_column(Float, nullable=True)
    unit: Mapped[str] = mapped_column(String(50), nullable=True)
    frequency: Mapped[str] = mapped_column(String(50), default="daily")  # hourly, daily, weekly, monthly
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class IndicatorReading(Base):
    """Historical readings for risk indicators"""
    __tablename__ = "indicator_readings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_id: Mapped[int] = mapped_column(Integer, ForeignKey("risk_indicators.id"))
    value: Mapped[float] = mapped_column(Float, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    notes: Mapped[str] = mapped_column(Text, nullable=True)

    # Relationships
    indicator: Mapped[RiskIndicator] = relationship("RiskIndicator")


class EnvironmentalChange(Base):
    """Environmental changes that could impact risk posture"""
    __tablename__ = "environmental_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    change_type: Mapped[str] = mapped_column(String(100), nullable=False)  # regulatory, technological, operational, etc.
    description: Mapped[str] = mapped_column(Text, nullable=True)
    impact_assessment: Mapped[str] = mapped_column(Text, nullable=True)
    risk_implications: Mapped[str] = mapped_column(Text, nullable=True)
    detection_date: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    assessment_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="detected")  # detected, assessed, mitigated
    severity: Mapped[str] = mapped_column(String(50), default="medium")  # low, medium, high, critical

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Compliance(Base):
    """
    Represents compliance assessment scores for regulatory and security frameworks.

    Tracks compliance status and scores across multiple frameworks including
    NIST, ISO, PCI DSS, HIPAA, and others. Supports automated and manual
    scoring with gap analysis and remediation tracking.

    Attributes:
        framework: Compliance framework name
        control: Specific control identifier
        control_family: Control family/category
        score: Compliance score (0-100%)
        status: Compliance status (compliant, non-compliant, not_assessed)
        automated_score: AI-calculated score
        manual_override: Whether score was manually set
        assessment_method: How assessment was performed

    Relationships:
        risk: Associated risk assessment (optional)

    Scoring Methods:
        - Automated: Calculated based on risk mitigation status
        - Manual: Directly set by compliance officers
        - Hybrid: Combination of automated and manual assessment

    Usage:
        Used for compliance monitoring and reporting
        Supports multiple framework assessments simultaneously
        Enables gap analysis and remediation planning
    """
    __tablename__ = "compliance_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[str] = mapped_column(String(255), nullable=False)
    control: Mapped[str] = mapped_column(String(255), nullable=False)
    control_family: Mapped[str] = mapped_column(String(100), nullable=True)  # e.g., AC, IR, AU
    score: Mapped[float] = mapped_column(Float, default=0.0)           # percentage compliance 0-100
    status: Mapped[str] = mapped_column(String(50), default="not_assessed")  # compliant, non-compliant, not_assessed
    automated_score: Mapped[float] = mapped_column(Float, default=0.0)     # Automated calculated score
    manual_override: Mapped[bool] = mapped_column(Boolean, default=False)  # Whether score was manually overridden
    assessment_method: Mapped[str] = mapped_column(String(100), default="manual")  # manual, automated, hybrid

    risk_id: Mapped[int] = mapped_column(Integer, ForeignKey("risks.id"), nullable=True)
    risk = relationship("Risk", back_populates="compliance")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def calculate_automated_score(self):
        """
        Calculate automated compliance score based on associated risk mitigation status.

        Analyzes the linked risk assessment to determine compliance level based on
        treatment effectiveness and residual risk. Provides objective scoring
        for controls that can be automatically assessed.

        Side Effects:
            Updates self.automated_score attribute with calculated value

        Scoring Logic:
            - Base score: 50% (moderate compliance)
            - Mitigation treatment: +30% for proper mitigation plans
            - Risk acceptance: +10% for accepted but monitored risks
            - Risk avoidance: +40% for avoided risks
            - Residual risk adjustment: ±20% based on post-mitigation risk level

        Note:
            Requires associated risk record for calculation
            Used when manual_override is False
            Supports automated compliance monitoring
        """
        if self.risk:
            # Base score on risk treatment and mitigation effectiveness
            base_score = 50.0  # Default moderate compliance

            if self.risk.treatment == RiskTreatment.MITIGATE and self.risk.mitigation_plan:
                base_score += 30.0  # Good mitigation plan
            elif self.risk.treatment == RiskTreatment.ACCEPT:
                base_score += 10.0  # Risk accepted but monitored
            elif self.risk.treatment == RiskTreatment.AVOID:
                base_score += 40.0  # Risk avoided

            # Adjust based on residual risk
            if hasattr(self.risk, 'residual_score') and self.risk.residual_score:
                residual_factor = (25 - self.risk.residual_score) / 25.0  # Lower residual = higher compliance
                base_score += residual_factor * 20.0

            self.automated_score = min(100.0, max(0.0, base_score))
        else:
            self.automated_score = 0.0

    def get_effective_score(self):
        """
        Get the effective compliance score, prioritizing manual overrides.

        Returns the manually set score if manual_override is enabled,
        otherwise returns the automated calculated score.

        Returns:
            float: Effective compliance score (0-100)

        Priority Logic:
            1. Manual score (if manual_override = True)
            2. Automated score (if manual_override = False)

        Note:
            Supports compliance officer overrides for complex assessments
            Maintains audit trail of manual vs automated scoring
            Used for reporting and compliance status determination
        """
        if self.manual_override:
            return self.score
        return self.automated_score


class ComplianceScore(Base):
    """Automated compliance scoring system for regulatory requirements."""
    __tablename__ = "compliance_scores_automated"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., "NIST-AC-2", "GDPR-25"
    calculated_score: Mapped[float] = mapped_column(Float, default=0.0)       # 0-100 percentage
    weight: Mapped[float] = mapped_column(Float, default=1.0)                 # Importance weight for overall scoring
    assessment_date: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Gap analysis fields
    gap_description: Mapped[str] = mapped_column(Text, nullable=True)
    remediation_plan: Mapped[str] = mapped_column(Text, nullable=True)
    priority_level: Mapped[str] = mapped_column(String(20), default="medium")  # high, medium, low

    # Relationships
    requirement_id_fk: Mapped[int] = mapped_column(Integer, ForeignKey("compliance_requirements.id"), nullable=True)
    requirement = relationship("ComplianceRequirement", backref="automated_scores")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def calculate_gap_score(self, target_score: float = 100.0):
        """Calculate compliance gap as percentage"""
        return max(0.0, target_score - self.calculated_score)

    def get_compliance_status(self):
        """Get compliance status based on score"""
        if self.calculated_score >= 95.0:
            return "compliant"
        elif self.calculated_score >= 80.0:
            return "mostly_compliant"
        elif self.calculated_score >= 60.0:
            return "partially_compliant"
        else:
            return "non_compliant"


class Dependency(Base):
    """
    Represents software dependencies with automated risk assessment and vulnerability tracking.

    Tracks third-party libraries and packages used in applications, performing
    automated risk analysis based on known vulnerabilities and version analysis.
    Supports supply chain risk management and dependency security monitoring.

    Attributes:
        name: Package/library name (e.g., "flask", "requests")
        version: Installed version string
        risk_level: Automatically assessed risk severity
        vulnerabilities: Known CVEs or security issues
        risk: Human-readable risk description
        mitigation: Recommended fix or upgrade path
        mitigation_suggestions: Detailed mitigation strategies

    Risk Assessment:
        - Automated analysis based on package name and version
        - Known vulnerable versions trigger appropriate risk levels
        - Supports major frameworks (Flask, Requests, etc.)

    Usage:
        Populated through dependency scanning tools
        Used for security assessments and compliance reporting
        Supports automated vulnerability management workflows
    """
    __tablename__ = "dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    version: Mapped[str] = mapped_column(String, nullable=False)
    risk_level: Mapped[RiskSeverity] = mapped_column(Enum(RiskSeverity), default=RiskSeverity.LOW)
    vulnerabilities: Mapped[str] = mapped_column(Text, nullable=True)  # List of CVEs or known issues
    risk: Mapped[str] = mapped_column(String)         # e.g., CVE found / None
    mitigation: Mapped[str] = mapped_column(String)   # recommended fix
    mitigation_suggestions: Mapped[str] = mapped_column(Text, nullable=True)  # Detailed mitigation strategies
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_checked: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def assess_risk(self):
        """
        Assess supply chain and security risks based on dependency name and version.

        Performs automated risk analysis using known vulnerability patterns and
        version-specific security issues. Updates risk level, vulnerabilities,
        and mitigation recommendations based on package characteristics.

        Side Effects:
            Updates multiple attributes with assessment results:
            - risk_level: RiskSeverity enum value
            - vulnerabilities: Known security issues
            - risk: Human-readable risk description
            - mitigation: Recommended actions
            - mitigation_suggestions: Detailed remediation steps

        Assessment Logic:
            - Flask < 2.0: High risk (known vulnerabilities)
            - Requests < 2.25.0: Medium risk (information disclosure)
            - Other dependencies: Low risk by default

        Note:
            Uses hardcoded vulnerability knowledge
            In production, integrate with vulnerability databases (NVD, etc.)
            Supports extensible risk assessment rules
        """
        # Example: Outdated Flask versions
        if self.name.lower() == "flask" and self.version.startswith("1."):
            self.risk_level = RiskSeverity.HIGH
            self.vulnerabilities = "CVE-2021-1234 (Injection vulnerability), CVE-2022-5678 (XSS vulnerability)"
            self.risk = "High risk due to known vulnerabilities in Flask 1.x"
            self.mitigation = "Upgrade to Flask 2.x or later"
            self.mitigation_suggestions = "1. Update to Flask 2.3.2 or newer. 2. Use virtual environment. 3. Regularly scan for vulnerabilities using tools like Safety or Bandit. 4. Implement dependency pinning in requirements.txt."
        # Example: Vulnerable requests library
        elif self.name.lower() == "requests" and self.version < "2.25.0":
            self.risk_level = RiskSeverity.MEDIUM
            self.vulnerabilities = "CVE-2021-28363 (Information disclosure)"
            self.risk = "Medium risk due to potential information disclosure"
            self.mitigation = "Upgrade to requests 2.25.0 or later"
            self.mitigation_suggestions = "1. Upgrade to requests >= 2.25.0. 2. Use HTTPS URLs. 3. Validate SSL certificates. 4. Monitor for security advisories."
        else:
            self.risk_level = RiskSeverity.LOW
            self.vulnerabilities = None
            self.risk = "No known vulnerabilities"
            self.mitigation = "Keep updated"
            self.mitigation_suggestions = "1. Regularly update dependencies. 2. Use dependency scanning tools. 3. Review changelogs for security fixes."


class Incident(Base):
    """Represents security incidents reported in the system."""
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    severity: Mapped[IncidentSeverity] = mapped_column(Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM)

    reported_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reported_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # IRP Step Notes
    preparation_notes: Mapped[str] = mapped_column(Text, nullable=True)
    identification_notes: Mapped[str] = mapped_column(Text, nullable=True)
    containment_notes: Mapped[str] = mapped_column(Text, nullable=True)
    eradication_notes: Mapped[str] = mapped_column(Text, nullable=True)
    recovery_notes: Mapped[str] = mapped_column(Text, nullable=True)

    # Relationships
    reporter: Mapped["User"] = relationship("User", back_populates="incidents")
    evidence: Mapped[list["Evidence"]] = relationship("Evidence", back_populates="incident")

    def __repr__(self):
        return f"<Incident(id={self.id}, title='{self.title}', status={self.status.value})>"


class Evidence(Base):
    """Represents evidence collected for incidents."""
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[EvidenceType] = mapped_column(Enum(EvidenceType), nullable=False)
    file_path: Mapped[str] = mapped_column(String(512), nullable=True)  # For file-based evidence
    description: Mapped[str] = mapped_column(Text, nullable=False)
    collected_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    storage_method: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., "Secure server storage", "Encrypted external drive"
    hash_value: Mapped[str] = mapped_column(String(128), nullable=True)  # SHA-256 hash for integrity
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=True)

    # Relationships
    collector: Mapped["User"] = relationship("User", back_populates="evidence")
    incident: Mapped["Incident"] = relationship("Incident", back_populates="evidence")

    def __repr__(self):
        return f"<Evidence(id={self.id}, type={self.type.value}, collected_at={self.collected_at})>"


class AuditLog(Base):
    """
    Audit log for tracking governance and security events.

    Implements comprehensive audit logging for governance compliance:
    - User authentication events
    - Role changes and administrative actions
    - Security policy violations
    - Data access patterns
    - Incident response activities

    Audit Categories:
    - AUTHENTICATION: Login/logout events
    - AUTHORIZATION: Access control decisions
    - ADMINISTRATION: Administrative actions
    - COMPLIANCE: Policy compliance events
    - SECURITY: Security-related events
    """
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)  # Nullable for system events
    action: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., "LOGIN", "ROLE_CHANGE", "ACCESS_DENIED"
    category: Mapped[str] = mapped_column(String(50), nullable=False)  # AUTHENTICATION, AUTHORIZATION, ADMINISTRATION, COMPLIANCE, SECURITY
    description: Mapped[str] = mapped_column(Text, nullable=False)  # Detailed description of the event
    resource: Mapped[str] = mapped_column(String(255), nullable=True)  # Resource accessed (e.g., "/admin/users")
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)  # IPv4/IPv6 address
    user_agent: Mapped[str] = mapped_column(String(500), nullable=True)  # Browser/client information
    success: Mapped[bool] = mapped_column(Boolean, default=True)  # Whether the action was successful

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="audit_logs")

    def __repr__(self):
        return f"<AuditLog(id={self.id}, action='{self.action}', category='{self.category}', user_id={self.user_id})>"


class ComplianceMatrix(Base):
    """Maps compliance requirements to controls and risks."""
    __tablename__ = "compliance_matrix"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=False)
    requirement: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., "GDPR Article 25"
    control_mapping: Mapped[str] = mapped_column(String(255), nullable=True)  # e.g., "NIST AC-2"
    risk_category: Mapped[RiskCategory] = mapped_column(Enum(RiskCategory), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    assessment_procedure: Mapped[str] = mapped_column(Text, nullable=True)
    evidence_required: Mapped[str] = mapped_column(Text, nullable=True)

    # Compliance scoring
    current_score: Mapped[float] = mapped_column(Float, default=0.0)
    target_score: Mapped[float] = mapped_column(Float, default=100.0)
    last_assessed: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    next_assessment: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class RiskApproval(Base):
    """Represents risk approval workflow and decision-making process."""
    __tablename__ = "risk_approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id"), nullable=False)
    approver_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    status: Mapped[ApprovalStatus] = mapped_column(Enum(ApprovalStatus), default=ApprovalStatus.PENDING)
    decision_notes: Mapped[str] = mapped_column(Text, nullable=True)
    approval_level: Mapped[str] = mapped_column(String(50), nullable=True)  # business_unit, department, executive
    escalated_to: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    requested_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    decided_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    risk = relationship("Risk", backref="approvals")
    approver = relationship("User", foreign_keys=[approver_id])
    escalated_user = relationship("User", foreign_keys=[escalated_to])


class GovernanceDecision(Base):
    """Tracks governance decisions and their rationale."""
    __tablename__ = "governance_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    decision_type: Mapped[str] = mapped_column(String(100), nullable=False)  # risk_treatment, policy_change, control_implementation
    decision_maker: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=True)
    alternatives_considered: Mapped[str] = mapped_column(Text, nullable=True)
    expected_outcomes: Mapped[str] = mapped_column(Text, nullable=True)

    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id"), nullable=True)
    compliance_id: Mapped[int] = mapped_column(ForeignKey("compliance_scores.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    implemented_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    decision_maker_user = relationship("User", backref="governance_decisions")
    risk = relationship("Risk", backref="governance_decisions")
    compliance = relationship("Compliance", backref="governance_decisions")


class ComplianceRequirement(Base):
    """Detailed compliance requirements for regulatory standards."""
    __tablename__ = "compliance_requirements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=False)
    requirement_id: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., "GDPR-25", "NIST-AC-2"
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(100), nullable=True)  # e.g., "Data Protection", "Access Control"
    mandatory: Mapped[bool] = mapped_column(Boolean, default=True)  # Whether compliance is required
    assessment_frequency: Mapped[str] = mapped_column(String(50), default="annual")  # annual, quarterly, monthly

    # Relationships
    mappings: Mapped[list["RiskComplianceMapping"]] = relationship("RiskComplianceMapping", back_populates="requirement")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class RiskComplianceMapping(Base):
    """Maps risks to specific compliance requirements."""
    __tablename__ = "risk_compliance_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id"), nullable=False)
    requirement_id: Mapped[int] = mapped_column(ForeignKey("compliance_requirements.id"), nullable=False)
    mapping_type: Mapped[str] = mapped_column(String(50), default="direct")  # direct, indirect, related
    impact_level: Mapped[str] = mapped_column(String(50), nullable=True)  # High, Medium, Low
    notes: Mapped[str] = mapped_column(Text, nullable=True)  # Additional mapping details

    # Relationships
    risk: Mapped["Risk"] = relationship("Risk", backref="compliance_mappings")
    requirement: Mapped["ComplianceRequirement"] = relationship("ComplianceRequirement", back_populates="mappings")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class BrainstormingSession(Base):
    """Represents a structured brainstorming session for risk identification."""
    __tablename__ = "brainstorming_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    facilitator: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="planning")  # planning, active, completed, cancelled

    # Session details
    scheduled_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    duration_minutes: Mapped[int] = mapped_column(Integer, default=60)
    max_participants: Mapped[int] = mapped_column(Integer, default=10)

    # Methodology settings
    technique: Mapped[str] = mapped_column(String(100), default="round_robin")  # round_robin, silent, affinity, etc.
    time_limit_per_idea: Mapped[int] = mapped_column(Integer, default=2)  # minutes per idea
    voting_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Results
    total_ideas_generated: Mapped[int] = mapped_column(Integer, default=0)
    ideas_converted_to_risks: Mapped[int] = mapped_column(Integer, default=0)

    # Documentation
    agenda: Mapped[str] = mapped_column(Text, nullable=True)
    ground_rules: Mapped[str] = mapped_column(Text, nullable=True)
    session_notes: Mapped[str] = mapped_column(Text, nullable=True)
    outcomes: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    facilitator_user = relationship("User", backref="facilitated_sessions")
    participants: Mapped[list["BrainstormingParticipant"]] = relationship("BrainstormingParticipant", back_populates="session")
    ideas: Mapped[list["BrainstormingIdea"]] = relationship("BrainstormingIdea", back_populates="session")

    def get_participant_count(self):
        """Get current number of participants"""
        return len(self.participants)

    def get_completion_percentage(self):
        """Calculate session completion percentage"""
        if self.status == "completed":
            return 100
        elif self.status == "active":
            return 50
        elif self.status == "planning":
            return 25
        return 0


class BrainstormingParticipant(Base):
    """Represents participants in a brainstorming session."""
    __tablename__ = "brainstorming_participants"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("brainstorming_sessions.id"), nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="participant")  # facilitator, participant, observer
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Participation metrics
    ideas_contributed: Mapped[int] = mapped_column(Integer, default=0)
    votes_cast: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    session = relationship("BrainstormingSession", back_populates="participants")
    user = relationship("User", backref="brainstorming_participations")
    ideas: Mapped[list["BrainstormingIdea"]] = relationship("BrainstormingIdea", back_populates="contributor")


class BrainstormingIdea(Base):
    """Represents individual ideas generated during brainstorming."""
    __tablename__ = "brainstorming_ideas"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[int] = mapped_column(ForeignKey("brainstorming_sessions.id"), nullable=False)
    contributor_id: Mapped[int] = mapped_column(ForeignKey("brainstorming_participants.id"), nullable=False)

    # Idea content
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=True)  # strategic, operational, financial, etc.

    # Evaluation
    votes: Mapped[int] = mapped_column(Integer, default=0)
    priority_score: Mapped[int] = mapped_column(Integer, default=0)  # 1-5 scale

    # Conversion to risk
    converted_to_risk: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    session = relationship("BrainstormingSession", back_populates="ideas")
    contributor = relationship("BrainstormingParticipant", back_populates="ideas")
    risk = relationship("Risk", backref="brainstorming_idea")


class RiskChecklist(Base):
    """Represents predefined risk checklists for different domains."""
    __tablename__ = "risk_checklists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)  # IT, Finance, Operations, Compliance, etc.
    framework: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=True)

    # Checklist metadata
    version: Mapped[str] = mapped_column(String(20), default="1.0")
    is_template: Mapped[bool] = mapped_column(Boolean, default=True)  # Template vs custom checklist
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Usage tracking
    times_used: Mapped[int] = mapped_column(Integer, default=0)
    last_used: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", backref="created_checklists")
    items: Mapped[list["RiskChecklistItem"]] = relationship("RiskChecklistItem", back_populates="checklist")
    assessments: Mapped[list["RiskChecklistAssessment"]] = relationship("RiskChecklistAssessment", back_populates="checklist")


class RiskChecklistItem(Base):
    """Represents individual items within a risk checklist."""
    __tablename__ = "risk_checklist_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    checklist_id: Mapped[int] = mapped_column(ForeignKey("risk_checklists.id"), nullable=False)

    # Item details
    question: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    category: Mapped[RiskCategory] = mapped_column(Enum(RiskCategory), nullable=True)

    # Risk mapping
    default_likelihood: Mapped[int] = mapped_column(Integer, default=3)  # 1-5 scale
    default_impact: Mapped[int] = mapped_column(Integer, default=3)      # 1-5 scale
    suggested_controls: Mapped[str] = mapped_column(Text, nullable=True)

    # Ordering
    order: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    checklist = relationship("RiskChecklist", back_populates="items")


class RiskChecklistAssessment(Base):
    """Represents an assessment conducted using a risk checklist."""
    __tablename__ = "risk_checklist_assessments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    checklist_id: Mapped[int] = mapped_column(ForeignKey("risk_checklists.id"), nullable=False)
    assessor_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    # Assessment details
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="in_progress")  # in_progress, completed, reviewed

    # Results
    total_items: Mapped[int] = mapped_column(Integer, default=0)
    completed_items: Mapped[int] = mapped_column(Integer, default=0)
    risks_identified: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    checklist = relationship("RiskChecklist", back_populates="assessments")
    assessor = relationship("User", backref="checklist_assessments")
    responses: Mapped[list["RiskChecklistResponse"]] = relationship("RiskChecklistResponse", back_populates="assessment")


class RiskChecklistResponse(Base):
    """Represents responses to individual checklist items."""
    __tablename__ = "risk_checklist_responses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    assessment_id: Mapped[int] = mapped_column(ForeignKey("risk_checklist_assessments.id"), nullable=False)
    item_id: Mapped[int] = mapped_column(ForeignKey("risk_checklist_items.id"), nullable=False)

    # Response data
    response: Mapped[str] = mapped_column(String(50), nullable=False)  # yes, no, n/a
    notes: Mapped[str] = mapped_column(Text, nullable=True)

    # Risk creation
    risk_created: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    assessment = relationship("RiskChecklistAssessment", back_populates="responses")
    item = relationship("RiskChecklistItem", backref="responses")
    risk = relationship("Risk", backref="checklist_response")


class SWOTAnalysis(Base):
    """Represents a SWOT analysis for strategic risk assessment."""
    __tablename__ = "swot_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[str] = mapped_column(Text, nullable=True)  # What is being analyzed

    # SWOT dimensions
    strengths: Mapped[str] = mapped_column(Text, nullable=True)
    weaknesses: Mapped[str] = mapped_column(Text, nullable=True)
    opportunities: Mapped[str] = mapped_column(Text, nullable=True)
    threats: Mapped[str] = mapped_column(Text, nullable=True)

    # Analysis metadata
    analyst_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft, in_review, completed, archived

    # Risk conversion
    risks_from_threats: Mapped[int] = mapped_column(Integer, default=0)
    risks_from_weaknesses: Mapped[int] = mapped_column(Integer, default=0)

    # Strategic insights
    key_findings: Mapped[str] = mapped_column(Text, nullable=True)
    recommendations: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    analyst = relationship("User", backref="swot_analyses")
    items: Mapped[list["SWOTItem"]] = relationship("SWOTItem", back_populates="analysis")

    def get_completion_percentage(self):
        """Calculate SWOT completion percentage based on filled sections"""
        sections = [self.strengths, self.weaknesses, self.opportunities, self.threats]
        filled_sections = sum(1 for section in sections if section and section.strip())
        return (filled_sections / 4) * 100


class SWOTItem(Base):
    """Represents individual items within SWOT analysis."""
    __tablename__ = "swot_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("swot_analyses.id"), nullable=False)

    # Item details
    dimension: Mapped[str] = mapped_column(String(20), nullable=False)  # strengths, weaknesses, opportunities, threats
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Evaluation
    importance: Mapped[int] = mapped_column(Integer, default=3)  # 1-5 scale
    feasibility: Mapped[int] = mapped_column(Integer, default=3)  # 1-5 scale for opportunities
    impact: Mapped[int] = mapped_column(Integer, default=3)       # 1-5 scale for threats

    # Risk conversion
    converted_to_risk: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    analysis = relationship("SWOTAnalysis", back_populates="items")
    risk = relationship("Risk", backref="swot_item")


class RiskIdentificationMethod(Base):
    """Tracks which risk identification method was used for each risk."""
    __tablename__ = "risk_identification_methods"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id"), nullable=False)

    # Method identification
    method: Mapped[str] = mapped_column(String(50), nullable=False)  # brainstorming, checklist, swot, scan, manual
    method_id: Mapped[int] = mapped_column(Integer, nullable=True)  # ID of the source method record

    # Context
    identified_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    identified_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    risk = relationship("Risk", backref="identification_methods")
    identifier = relationship("User", backref="risk_identifications")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class CriticalAssetRegister(Base):
    """Critical Asset Risk Exposure Register showing threat exposure, vulnerabilities, and interconnection dependencies."""
    __tablename__ = "critical_asset_register"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_name: Mapped[str] = mapped_column(String(255), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., "Database", "Application", "Network"
    asset_value: Mapped[float] = mapped_column(Float, default=0.0)
    criticality_level: Mapped[str] = mapped_column(String(20), default="medium")  # high, medium, low
    
    # Threat exposure
    threat_exposure_score: Mapped[int] = mapped_column(Integer, default=1)  # 1-5 scale
    primary_threats: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list of threats
    
    # Vulnerabilities
    vulnerability_count: Mapped[int] = mapped_column(Integer, default=0)
    critical_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    vulnerability_details: Mapped[str] = mapped_column(Text, nullable=True)  # JSON details
    
    # Interconnection dependencies
    upstream_dependencies: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list
    downstream_dependencies: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list
    dependency_risk_score: Mapped[int] = mapped_column(Integer, default=1)  # 1-5 scale
    
    # Risk exposure calculation
    overall_risk_exposure: Mapped[int] = mapped_column(Integer, default=1)  # Calculated 1-5 scale
    
    # Associated risk
    risk_id: Mapped[int] = mapped_column(ForeignKey("risks.id"), nullable=True)
    
    # Metadata
    assessed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    last_assessment: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    next_review: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    assessor = relationship("User", backref="asset_assessments")
    risk = relationship("Risk", backref="asset_register_entries")


    def calculate_overall_risk_exposure(self):
        """Calculate overall risk exposure based on threat, vulnerability, and dependency factors"""
        threat_factor = self.threat_exposure_score
        vulnerability_factor = min(self.critical_vulnerabilities + 1, 5)
        dependency_factor = self.dependency_risk_score
        
        # Weighted calculation
        self.overall_risk_exposure = int((threat_factor * 0.4 + vulnerability_factor * 0.4 + dependency_factor * 0.2))
        return self.overall_risk_exposure

    def get_threat_list(self):
        """Parse and return threat list"""
        import json
        try:
            return json.loads(self.primary_threats or '[]')
        except json.JSONDecodeError:
            return []

    def get_vulnerability_details(self):
        """Parse and return vulnerability details"""
        import json
        try:
            return json.loads(self.vulnerability_details or '{}')
        except json.JSONDecodeError:
            return {}

    def get_dependency_network(self):
        """Return structured dependency information"""
        import json
        return {
            'upstream': json.loads(self.upstream_dependencies or '[]'),
            'downstream': json.loads(self.downstream_dependencies or '[]')
        }

    def generate_report(self):
        """Generate professional formatted report"""
        return f"""
            CRITICAL ASSET RISK EXPOSURE REPORT
            ===================================

            Asset: {self.asset_name}
            Type: {self.asset_type}
            Value: ${self.asset_value:.2f}
            Criticality: {self.criticality_level.upper()}

            THREAT EXPOSURE
            ---------------
            Score: {self.threat_exposure_score}/5
            Primary Threats: {', '.join(self.get_threat_list())}

            VULNERABILITIES
            ---------------
            Total Vulnerabilities: {self.vulnerability_count}
            Critical Vulnerabilities: {self.critical_vulnerabilities}

            INTERCONNECTION DEPENDENCIES
            -----------------------------
            Upstream Dependencies: {len(self.get_dependency_network()['upstream'])}
            Downstream Dependencies: {len(self.get_dependency_network()['downstream'])}
            Dependency Risk Score: {self.dependency_risk_score}/5

            OVERALL RISK EXPOSURE: {self.overall_risk_exposure}/5
            {'⚠️  HIGH RISK - Immediate attention required' if self.overall_risk_exposure >= 4 else '✓ Acceptable risk level'}

            Assessed by: {self.assessor.email if self.assessor else 'Unknown'}
            Last Assessment: {self.last_assessment.strftime('%Y-%m-%d')}
            Next Review: {self.next_review.strftime('%Y-%m-%d') if self.next_review else 'Not scheduled'}
"""

class IndicatorOfCompromise(Base):
    """Represents Indicators of Compromise (IoCs) for threat intelligence"""
    __tablename__ = "indicators_of_compromise"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    indicator_type: Mapped[str] = mapped_column(String(50), nullable=False)  # ip, domain, hash, url, email, etc.
    indicator_value: Mapped[str] = mapped_column(String(500), nullable=False)  # The actual IoC value
    confidence: Mapped[int] = mapped_column(Integer, default=50)  # 0-100 confidence level
    severity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical
    status: Mapped[str] = mapped_column(String(20), default="active")  # active, retired, false_positive

    # Threat context
    threat_actor: Mapped[str] = mapped_column(String(100), nullable=True)
    campaign: Mapped[str] = mapped_column(String(100), nullable=True)
    malware_family: Mapped[str] = mapped_column(String(100), nullable=True)

    # Detection information
    first_seen: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    detection_source: Mapped[str] = mapped_column(String(100), nullable=True)  # e.g., "VirusTotal", "Custom Analysis"

    # Metadata
    description: Mapped[str] = mapped_column(Text, nullable=True)
    tags: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of tags
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", backref="created_iocs")
    analyses: Mapped[list["IoCAnalysis"]] = relationship("IoCAnalysis", back_populates="ioc")


class IoCAnalysis(Base):
    """Analysis of Indicators of Compromise"""
    __tablename__ = "ioc_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_id: Mapped[int] = mapped_column(ForeignKey("indicators_of_compromise.id"), nullable=False)

    # Analysis details
    analysis_type: Mapped[str] = mapped_column(String(50), nullable=False)  # behavioral, static, network, etc.
    detection_method: Mapped[str] = mapped_column(String(100), nullable=False)  # How it was detected
    threat_indication: Mapped[str] = mapped_column(Text, nullable=False)  # How it indicates a threat

    # Technical details
    analysis_result: Mapped[str] = mapped_column(Text, nullable=True)  # Detailed analysis findings
    mitigation_steps: Mapped[str] = mapped_column(Text, nullable=True)  # Recommended actions
    false_positive_probability: Mapped[int] = mapped_column(Integer, default=0)  # 0-100

    # Validation
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    validated_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    validation_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Metadata
    analyst_notes: Mapped[str] = mapped_column(Text, nullable=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    ioc = relationship("IndicatorOfCompromise", back_populates="analyses")
    analyst = relationship("User", foreign_keys=[created_by])
    validator = relationship("User", foreign_keys=[validated_by])


class DetectionRule(Base):
    """Detection rules for automated threat detection and alerting"""
    __tablename__ = "detection_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=False)  # threshold-based, anomaly-based, signature-based, etc.

    # Conditions (stored as JSON for flexibility)
    conditions: Mapped[str] = mapped_column(Text, nullable=False)  # JSON array of conditions

    severity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical
    actions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of actions to take
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Metadata
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    last_triggered: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", backref="detection_rules")


class MalwareSample(Base):
    """Malware sample submissions for analysis"""
    __tablename__ = "malware_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_hash: Mapped[str] = mapped_column(String(128), nullable=False)  # SHA256 hash
    filename: Mapped[str] = mapped_column(String(255), nullable=True)
    analysis_status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, analyzing, completed, failed
    submitted_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    submitter = relationship("User", backref="malware_samples")


class MalwareAnalysis(Base):
    """Malware analysis results"""
    __tablename__ = "malware_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sample_id: Mapped[int] = mapped_column(ForeignKey("malware_samples.id"), nullable=False)
    platform: Mapped[str] = mapped_column(String(100), nullable=False)  # virustotal, hybrid-analysis, etc.
    detection_ratio: Mapped[str] = mapped_column(String(20), nullable=True)  # e.g., "15/70"
    positive_detections: Mapped[int] = mapped_column(Integer, default=0)
    total_scanners: Mapped[int] = mapped_column(Integer, default=0)
    behavioral_indicators: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string
    potential_impact: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="low")  # low, medium, high, critical

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    sample = relationship("MalwareSample", backref="analyses")


class PhishingTemplate(Base):
    """Phishing email templates for security awareness"""
    __tablename__ = "phishing_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=True)
    body_html: Mapped[str] = mapped_column(Text, nullable=True)
    body_text: Mapped[str] = mapped_column(Text, nullable=True)
    spoofed_sender: Mapped[str] = mapped_column(String(255), nullable=True)
    malicious_links: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array
    social_engineering_techniques: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array
    risk_level: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", backref="phishing_templates")


class APTCampaign(Base):
    """Advanced Persistent Threat campaign documentation"""
    __tablename__ = "apt_campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    actor_name: Mapped[str] = mapped_column(String(255), nullable=True)
    target_sector: Mapped[str] = mapped_column(String(100), nullable=True)
    objectives: Mapped[str] = mapped_column(Text, nullable=True)
    techniques_used: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array
    indicators_of_compromise: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array
    severity: Mapped[str] = mapped_column(String(20), default="high")  # low, medium, high, critical
    relevance_to_organization: Mapped[str] = mapped_column(String(50), default="unknown")  # low, medium, high, direct
    documented_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    documenter = relationship("User", backref="apt_campaigns")


class ATTACKMapping(Base):
    """MITRE ATT&CK framework mappings for APT campaigns"""
    __tablename__ = "attack_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(ForeignKey("apt_campaigns.id"), nullable=False)
    tactic: Mapped[str] = mapped_column(String(255), nullable=True)
    technique: Mapped[str] = mapped_column(String(255), nullable=True)
    technique_id: Mapped[str] = mapped_column(String(20), nullable=True)  # e.g., T1059
    subtechnique: Mapped[str] = mapped_column(String(255), nullable=True)
    subtechnique_id: Mapped[str] = mapped_column(String(20), nullable=True)  # e.g., T1059.001
    description: Mapped[str] = mapped_column(Text, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=True)
    confidence: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high
    mapped_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    campaign = relationship("APTCampaign", backref="attack_mappings")
    mapper = relationship("User", backref="attack_mappings")


class VulnerabilityScan(Base):
    """Vulnerability scan records"""
    __tablename__ = "vulnerability_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_used: Mapped[str] = mapped_column(String(100), nullable=True)
    target_range: Mapped[str] = mapped_column(String(255), nullable=True)
    scan_type: Mapped[str] = mapped_column(String(50), default="basic")  # basic, comprehensive, compliance
    scan_parameters: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string
    vulnerabilities_found: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, default=0)
    start_time: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    end_time: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    duration_seconds: Mapped[int] = mapped_column(Integer, nullable=True)
    performed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    performer = relationship("User", backref="vulnerability_scans")


class VulnerabilityFinding(Base):
    """Individual vulnerability findings from scans"""
    __tablename__ = "vulnerability_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_scans.id"), nullable=False)
    host_ip: Mapped[str] = mapped_column(String(45), nullable=False)  # IPv4/IPv6
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    service: Mapped[str] = mapped_column(String(100), nullable=True)
    vulnerability_id: Mapped[str] = mapped_column(String(50), nullable=False)  # CVE-XXXX-XXXX
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # low, medium, high, critical
    cvss_score: Mapped[float] = mapped_column(Float, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    scan = relationship("VulnerabilityScan", backref="findings")


class AssetDiscovery(Base):
    """Asset discovery scan records"""
    __tablename__ = "asset_discoveries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_name: Mapped[str] = mapped_column(String(255), nullable=False)
    discovery_method: Mapped[str] = mapped_column(String(100), default="network_scan")
    target_network: Mapped[str] = mapped_column(String(255), nullable=True)
    scan_parameters: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string
    assets_discovered: Mapped[int] = mapped_column(Integer, default=0)
    critical_assets: Mapped[int] = mapped_column(Integer, default=0)
    network_topology: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string
    performed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    performer = relationship("User", backref="asset_discoveries")


class DiscoveredService(Base):
    """Services discovered on network assets"""
    __tablename__ = "discovered_services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset_discoveries.id"), nullable=False)
    service_name: Mapped[str] = mapped_column(String(100), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), default="tcp")
    state: Mapped[str] = mapped_column(String(20), nullable=False)  # open, closed, filtered
    criticality: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    asset = relationship("AssetDiscovery", backref="services")


class OpenCTIConnector(Base):
    """OpenCTI connector configurations"""
    __tablename__ = "opencti_connectors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False)  # import, export, internal
    description: Mapped[str] = mapped_column(Text, nullable=True)
    scope: Mapped[str] = mapped_column(String(50), nullable=True)  # threat-actor, observable, threat-intelligence
    configuration: Mapped[str] = mapped_column(Text, nullable=True)  # JSON configuration
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    last_run: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class MonitoringConfiguration(Base):
    """Security monitoring configuration settings"""
    __tablename__ = "monitoring_configurations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    retention_period_days: Mapped[int] = mapped_column(Integer, default=90)

    # System metrics
    cpu_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    memory_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    disk_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    network_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Log sources
    system_logs_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    application_logs_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    security_events_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Alert thresholds
    cpu_threshold: Mapped[int] = mapped_column(Integer, default=90)  # percentage
    memory_threshold: Mapped[int] = mapped_column(Integer, default=85)  # percentage
    disk_threshold: Mapped[int] = mapped_column(Integer, default=95)  # percentage
    network_threshold: Mapped[int] = mapped_column(Integer, default=1000)  # Mbps

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", backref="monitoring_configurations")


class OpenCTIIntegration(Base):
    """OpenCTI platform integration tracking"""
    __tablename__ = "opencti_integrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    platform_url: Mapped[str] = mapped_column(String(255), nullable=False)
    api_key: Mapped[str] = mapped_column(String(255), nullable=True)  # Encrypted in production
    status: Mapped[str] = mapped_column(String(20), default="disconnected")  # connected, disconnected, error
    last_sync: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    total_indicators: Mapped[int] = mapped_column(Integer, default=0)
    total_reports: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


# Data Archiving and Retention Models
class RetentionConfig(Base):
    """Configuration for data retention policies per table"""
    __tablename__ = "retention_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    table_name: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)  # e.g., "risks", "audit_logs", "incidents"
    retention_days: Mapped[int] = mapped_column(Integer, default=2555)  # 7 years in days
    archive_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auto_purge: Mapped[bool] = mapped_column(Boolean, default=False)  # Enable automatic purging of archived records
    last_archive_run: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    records_archived: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class RiskArchive(Base):
    """Archive table for old risk records - identical schema to risks table"""
    __tablename__ = "risk_archive"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset: Mapped[str] = mapped_column(String(500), nullable=False)
    threat: Mapped[str] = mapped_column(String(500), nullable=False)
    vulnerability: Mapped[str] = mapped_column(String(500), nullable=False)
    control: Mapped[str] = mapped_column(String(500), nullable=False)
    compliance_standard: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=True)
    status: Mapped[RiskStatus] = mapped_column(Enum(RiskStatus), default=RiskStatus.OPEN)
    category: Mapped[RiskCategory] = mapped_column(Enum(RiskCategory), nullable=True)

    likelihood: Mapped[int] = mapped_column(Integer, default=1)
    impact: Mapped[int] = mapped_column(Integer, default=1)
    score: Mapped[int] = mapped_column(Integer, default=0)

    severity: Mapped[RiskSeverity] = mapped_column(Enum(RiskSeverity), default=RiskSeverity.MEDIUM)

    ale: Mapped[float] = mapped_column(Float, default=0.0)
    emv: Mapped[float] = mapped_column(Float, default=0.0)

    mitigation_plan: Mapped[str] = mapped_column(Text, nullable=True)
    residual_risk: Mapped[str] = mapped_column(Text, nullable=True)
    owner: Mapped[str] = mapped_column(String(255), nullable=True)

    treatment: Mapped[RiskTreatment] = mapped_column(Enum(RiskTreatment), nullable=True)
    rmf_phase: Mapped[NIST_RMF_Phase] = mapped_column(Enum(NIST_RMF_Phase), default=NIST_RMF_Phase.PREPARE)
    approval_status: Mapped[ApprovalStatus] = mapped_column(Enum(ApprovalStatus), default=ApprovalStatus.PENDING)
    approver_id: Mapped[int] = mapped_column(Integer, nullable=True)

    asset_value: Mapped[float] = mapped_column(Float, default=0.0)
    mitigation_cost: Mapped[float] = mapped_column(Float, default=0.0)

    business_impact: Mapped[str] = mapped_column(Text, nullable=True)
    regulatory_impact: Mapped[str] = mapped_column(Text, nullable=True)
    risk_appetite_level: Mapped[int] = mapped_column(Integer, default=3)

    residual_likelihood: Mapped[int] = mapped_column(Integer, default=1)
    residual_impact: Mapped[int] = mapped_column(Integer, default=1)
    residual_score: Mapped[int] = mapped_column(Integer, default=0)

    escalation_level: Mapped[str] = mapped_column(String(50), default="business_unit")
    escalated_to: Mapped[int] = mapped_column(Integer, nullable=True)
    escalation_reason: Mapped[str] = mapped_column(Text, nullable=True)
    escalation_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    risk_tolerance_threshold: Mapped[int] = mapped_column(Integer, default=15)
    risk_appetite_alignment: Mapped[str] = mapped_column(Text, nullable=True)

    last_reviewed: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    next_review_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    review_frequency_days: Mapped[int] = mapped_column(Integer, default=90)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Multi-criteria risk scoring
    financial_impact: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    operational_impact: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    compliance_impact: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    reputation_impact: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    financial_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)
    operational_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)
    compliance_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)
    reputation_weight: Mapped[float] = mapped_column(Float, nullable=False, default=0.25)

    rto_hours: Mapped[float] = mapped_column(Float, nullable=True)
    rpo_hours: Mapped[float] = mapped_column(Float, nullable=True)
    mtd_hours: Mapped[float] = mapped_column(Float, nullable=True)
    financial_impact_amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    dependency_mapping: Mapped[str] = mapped_column(Text, nullable=True)

    annual_occurrence_probability: Mapped[float] = mapped_column(Float, nullable=True)
    ale_calculated: Mapped[float] = mapped_column(Float, nullable=True)
    emv_calculated: Mapped[float] = mapped_column(Float, nullable=True)

    evaluation_criteria: Mapped[str] = mapped_column(Text, nullable=True)
    stakeholder_approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    stakeholder_approval_notes: Mapped[str] = mapped_column(Text, nullable=True)

    mitigation_plan_json: Mapped[str] = mapped_column(Text, nullable=True)
    mitigation_plan_updated: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Archive metadata
    archived_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    archive_reason: Mapped[str] = mapped_column(String(255), default="retention_policy")


class AuditArchive(Base):
    """Archive table for old audit log records - identical schema to audit_logs table"""
    __tablename__ = "audit_archive"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str] = mapped_column(String(500), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Archive metadata
    archived_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    archive_reason: Mapped[str] = mapped_column(String(255), default="retention_policy")


class IncidentArchive(Base):
    """Archive table for old incident records - identical schema to incidents table"""
    __tablename__ = "incident_archive"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    severity: Mapped[IncidentSeverity] = mapped_column(Enum(IncidentSeverity), default=IncidentSeverity.MEDIUM)

    reported_by: Mapped[int] = mapped_column(Integer, nullable=False)
    reported_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    preparation_notes: Mapped[str] = mapped_column(Text, nullable=True)
    identification_notes: Mapped[str] = mapped_column(Text, nullable=True)
    containment_notes: Mapped[str] = mapped_column(Text, nullable=True)
    eradication_notes: Mapped[str] = mapped_column(Text, nullable=True)
    recovery_notes: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Archive metadata
    archived_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    archive_reason: Mapped[str] = mapped_column(String(255), default="retention_policy")