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

    # Risk status tracking for workflow optimization
    risk_status: Mapped[str] = mapped_column(String(50), default="unassessed")  # unassessed, risk_created: R123, mitigated, accepted

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

    # Chain of custody fields
    chain_of_custody: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string of custody history
    custody_status: Mapped[str] = mapped_column(String(50), default="collected")  # collected, transferred, analyzed, archived
    last_custody_update: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    custody_location: Mapped[str] = mapped_column(String(255), nullable=True)  # Current physical/digital location

    # Relationships
    collector: Mapped["User"] = relationship("User", back_populates="evidence")
    incident: Mapped["Incident"] = relationship("Incident", back_populates="evidence")

    def __repr__(self):
        return f"<Evidence(id={self.id}, type={self.type.value}, collected_at={self.collected_at})>"

    def update_chain_of_custody(self, action: str, user_id: int, location: str = None, notes: str = None):
        """
        Update the chain of custody for this evidence.

        Args:
            action: Action performed (collected, transferred, analyzed, archived)
            user_id: User performing the action
            location: New location of evidence
            notes: Additional notes about the action
        """
        import json
        from datetime import datetime, timezone

        current_time = datetime.now(timezone.utc)
        custody_entry = {
            "timestamp": current_time.isoformat(),
            "action": action,
            "user_id": user_id,
            "location": location or self.custody_location,
            "notes": notes
        }

        # Load existing chain or create new one
        if self.chain_of_custody:
            try:
                chain = json.loads(self.chain_of_custody)
            except json.JSONDecodeError:
                chain = []
        else:
            chain = []

        chain.append(custody_entry)
        self.chain_of_custody = json.dumps(chain, indent=2)
        self.custody_status = action
        self.last_custody_update = current_time
        if location:
            self.custody_location = location

    def get_chain_of_custody_history(self):
        """Get the complete chain of custody history."""
        import json
        if self.chain_of_custody:
            try:
                return json.loads(self.chain_of_custody)
            except json.JSONDecodeError:
                return []
        return []


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

    # Technical findings fields
    technical_findings: Mapped[str] = mapped_column(Text, nullable=True)  # JSON technical analysis findings
    extracted_iocs: Mapped[str] = mapped_column(Text, nullable=True)  # JSON extracted IoCs

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

    # Reverse engineering fields
    analysis_output: Mapped[str] = mapped_column(Text, nullable=True)  # JSON detailed analysis output

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

    # Advanced threat analysis fields
    analysis_type: Mapped[str] = mapped_column(String(100), nullable=True)  # comprehensive, targeted, reverse_engineering
    malware_sample: Mapped[str] = mapped_column(String(500), nullable=True)  # Associated malware sample hash
    reverse_engineering_output: Mapped[str] = mapped_column(Text, nullable=True)  # JSON reverse engineering findings
    attack_patterns: Mapped[str] = mapped_column(Text, nullable=True)  # JSON attack pattern analysis
    iocs_extracted: Mapped[str] = mapped_column(Text, nullable=True)  # JSON extracted IoCs

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

    # Attack pattern analysis fields
    detection_methods: Mapped[str] = mapped_column(Text, nullable=True)  # JSON detection methods
    mitigation_strategies: Mapped[str] = mapped_column(Text, nullable=True)  # JSON mitigation strategies
    attack_complexity: Mapped[str] = mapped_column(Text, nullable=True)  # JSON attack complexity analysis

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

    # Supply chain assessment fields
    assessment_scope: Mapped[str] = mapped_column(Text, nullable=True)  # JSON assessment scope
    supply_chain_findings: Mapped[str] = mapped_column(Text, nullable=True)  # JSON supply chain findings
    mitigation_recommendations: Mapped[str] = mapped_column(Text, nullable=True)  # JSON mitigation recommendations

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

    # Risk status tracking for workflow optimization
    risk_status: Mapped[str] = mapped_column(String(50), default="unassessed")  # unassessed, risk_created: R123, mitigated, accepted

    # Zero-day research fields
    research_methodology: Mapped[str] = mapped_column(Text, nullable=True)  # JSON research methodology
    zero_day_findings: Mapped[str] = mapped_column(Text, nullable=True)  # JSON zero-day findings

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    scan = relationship("VulnerabilityScan", backref="findings")


class AssetDiscovery(Base):
    """Advanced asset discovery scan records with relationship mapping and impact analysis"""
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

    # Advanced relationship mapping
    asset_relationships: Mapped[str] = mapped_column(Text, nullable=True)  # JSON dependency graph
    business_processes: Mapped[str] = mapped_column(Text, nullable=True)  # JSON business process mapping
    data_flows: Mapped[str] = mapped_column(Text, nullable=True)  # JSON data flow relationships

    # Impact analysis
    business_impact_assessment: Mapped[str] = mapped_column(Text, nullable=True)  # JSON impact analysis
    criticality_matrix: Mapped[str] = mapped_column(Text, nullable=True)  # JSON criticality scoring
    risk_exposure_score: Mapped[float] = mapped_column(Float, default=0.0)  # Overall risk exposure

    # Vulnerability correlation
    vulnerability_scan_id: Mapped[int] = mapped_column(ForeignKey("vulnerability_scans.id"), nullable=True)
    correlated_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    vulnerability_impact_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Advanced discovery features
    service_discovery_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    dependency_mapping_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    impact_analysis_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Performance metrics
    scan_duration_seconds: Mapped[int] = mapped_column(Integer, nullable=True)
    discovery_accuracy_score: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100 accuracy rating
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0)  # 0-100 percentage

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    performer = relationship("User", backref="asset_discoveries")
    vulnerability_scan = relationship("VulnerabilityScan", backref="asset_discoveries")

    def calculate_risk_exposure_score(self):
        """Calculate overall risk exposure based on asset criticality and vulnerabilities"""
        import json

        try:
            # Parse criticality matrix
            criticality_data = json.loads(self.criticality_matrix or '{}')
            avg_criticality = criticality_data.get('average_score', 3.0)

            # Factor in vulnerability impact
            vuln_factor = min(self.correlated_vulnerabilities / 10, 5) if self.correlated_vulnerabilities else 0

            # Calculate weighted score
            self.risk_exposure_score = (avg_criticality * 0.6) + (vuln_factor * 0.4)
            return self.risk_exposure_score
        except (json.JSONDecodeError, KeyError):
            return 0.0

    def generate_dependency_graph(self):
        """Generate a dependency graph from discovered assets and services"""
        import json

        graph = {
            'nodes': [],
            'edges': [],
            'metadata': {
                'total_assets': self.assets_discovered,
                'critical_assets': self.critical_assets,
                'generated_at': datetime.now(timezone.utc).isoformat()
            }
        }

        # This would be populated from actual discovery data
        # For now, return template structure
        return json.dumps(graph, indent=2)

    def assess_business_impact(self):
        """Perform business impact analysis for discovered assets"""
        import json

        impact_analysis = {
            'overall_impact_score': self.risk_exposure_score,
            'critical_business_processes': [],
            'impact_categories': {
                'financial': 0.0,
                'operational': 0.0,
                'compliance': 0.0,
                'reputational': 0.0
            },
            'recovery_priorities': [],
            'assessment_date': datetime.now(timezone.utc).isoformat()
        }

        # This would be populated based on asset criticality and business mapping
        return json.dumps(impact_analysis, indent=2)


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


class LogSource(Base):
    """Log sources for monitoring (Windows/Linux systems)"""
    __tablename__ = "log_sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)  # e.g., "Windows-DC01", "Linux-Web01"
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)  # "windows", "linux"
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # IPv4/IPv6
    status: Mapped[str] = mapped_column(String(20), default="connected")  # connected, disconnected, error
    last_connected: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    connection_protocol: Mapped[str] = mapped_column(String(50), default="syslog")  # syslog, winrm, snmp, etc.

    # Configuration
    log_types_enabled: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of enabled log types
    polling_interval: Mapped[int] = mapped_column(Integer, default=300)  # seconds

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    logs = relationship("CollectedLog", back_populates="source")


class CollectedLog(Base):
    """Individual log entries collected from monitoring sources"""
    __tablename__ = "collected_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("log_sources.id"), nullable=False)

    # Log metadata
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    log_type: Mapped[str] = mapped_column(String(50), nullable=False)  # security, system, application, auth, etc.
    severity: Mapped[str] = mapped_column(String(20), default="info")  # critical, error, warning, info, debug
    event_id: Mapped[str] = mapped_column(String(50), nullable=True)  # Windows Event ID or Linux facility.priority

    # Log content
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw_log: Mapped[str] = mapped_column(Text, nullable=True)  # Original raw log entry

    # Classification
    category: Mapped[str] = mapped_column(String(50), nullable=True)  # authentication, file_access, network_activity, etc.
    risk_score: Mapped[int] = mapped_column(Integer, default=0)  # 1-25 scale

    # Processing status
    processed: Mapped[bool] = mapped_column(Boolean, default=False)
    alert_generated: Mapped[bool] = mapped_column(Boolean, default=False)

    # Risk status tracking for workflow optimization
    risk_status: Mapped[str] = mapped_column(String(50), default="unassessed")  # unassessed, risk_created: R123, mitigated, accepted

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    source = relationship("LogSource", back_populates="logs")


class AlertRule(Base):
    """Alert rules for automated monitoring and alerting"""
    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Rule conditions
    log_type: Mapped[str] = mapped_column(String(50), nullable=True)  # security, system, auth, etc.
    severity: Mapped[str] = mapped_column(String(20), nullable=True)  # critical, error, warning
    category: Mapped[str] = mapped_column(String(50), nullable=True)  # authentication, file_access, network_activity
    keyword_match: Mapped[str] = mapped_column(String(255), nullable=True)  # Keywords to match in log messages

    # Thresholds
    threshold_count: Mapped[int] = mapped_column(Integer, default=1)  # Number of matching logs
    threshold_window: Mapped[int] = mapped_column(Integer, default=300)  # Time window in seconds

    # Actions
    alert_severity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical
    notification_channels: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of channels
    auto_response: Mapped[str] = mapped_column(Text, nullable=True)  # JSON automated response actions

    # Status
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", backref="alert_rules")


class Alert(Base):
    """Generated alerts from monitoring rules and manual alert documentation"""
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("alert_rules.id"), nullable=True)

    # Alert details
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical

    # Manual alert documentation fields
    category: Mapped[str] = mapped_column(String(100), nullable=True)
    impact: Mapped[str] = mapped_column(String(20), default="low")
    actions_taken: Mapped[str] = mapped_column(Text, nullable=True)

    # Trigger information
    triggered_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    source_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    log_entries: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of triggering log IDs

    # Status
    status: Mapped[str] = mapped_column(String(20), default="new")  # new, acknowledged, resolved, false_positive
    assigned_to: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    resolved_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    resolution_notes: Mapped[str] = mapped_column(Text, nullable=True)

    # Risk status tracking for workflow optimization
    risk_status: Mapped[str] = mapped_column(String(50), default="unassessed")  # unassessed, risk_created: R123, mitigated, accepted

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    rule = relationship("AlertRule", backref="alerts")
    assignee = relationship("User", foreign_keys=[assigned_to])


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
    incident_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=True)  # Auto-generated unique ID
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


# Advanced Compliance Strategy Models

class ComplianceStrategy(Base):
    """Strategic compliance planning for multinational organizations with regulatory conflict resolution."""

    __tablename__ = "compliance_strategies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    organization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Strategic scope
    geographic_scope: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of countries/regions
    industry_sector: Mapped[str] = mapped_column(String(100), nullable=True)
    employee_count: Mapped[int] = mapped_column(Integer, nullable=True)
    annual_revenue: Mapped[float] = mapped_column(Float, nullable=True)

    # Regulatory landscape
    primary_frameworks: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of primary compliance frameworks
    secondary_frameworks: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of secondary frameworks
    regulatory_bodies: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of regulatory bodies

    # Strategic objectives
    strategic_objectives: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of objectives
    risk_appetite_statement: Mapped[str] = mapped_column(Text, nullable=True)
    compliance_maturity_target: Mapped[str] = mapped_column(String(50), default="advanced")  # basic, intermediate, advanced, leading

    # Conflict resolution approach
    conflict_resolution_methodology: Mapped[str] = mapped_column(String(100), default="risk_based")  # risk_based, prescriptive, hybrid
    conflict_prioritization_criteria: Mapped[str] = mapped_column(Text, nullable=True)  # JSON criteria for prioritizing conflicts

    # Resource allocation
    total_budget: Mapped[float] = mapped_column(Float, default=0.0)
    fte_allocation: Mapped[int] = mapped_column(Integer, default=0)  # Full-time equivalent staff
    technology_budget: Mapped[float] = mapped_column(Float, default=0.0)

    # Governance
    strategy_owner: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    approval_authority: Mapped[str] = mapped_column(String(100), nullable=True)  # Board, Executive Committee, etc.
    review_frequency: Mapped[str] = mapped_column(String(50), default="annual")  # annual, semi-annual, quarterly

    # Status and tracking
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft, approved, active, under_review, retired
    version: Mapped[str] = mapped_column(String(20), default="1.0")
    effective_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    next_review_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    owner = relationship("User", backref="compliance_strategies")
    architectures = relationship("ComplianceArchitecture", back_populates="strategy", cascade="all, delete-orphan")
    roadmaps = relationship("ComplianceRoadmap", back_populates="strategy", cascade="all, delete-orphan")
    conflicts = relationship("RegulatoryConflict", back_populates="strategy", cascade="all, delete-orphan")


class RegulatoryConflict(Base):
    """Regulatory conflicts and resolution strategies for multinational compliance."""

    __tablename__ = "regulatory_conflicts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    strategy_id: Mapped[int] = mapped_column(Integer, ForeignKey("compliance_strategies.id"), nullable=False)

    # Conflict details
    conflict_title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Conflicting requirements
    framework_a: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=False)
    requirement_a: Mapped[str] = mapped_column(String(255), nullable=False)
    framework_b: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=False)
    requirement_b: Mapped[str] = mapped_column(String(255), nullable=False)

    # Geographic/business context
    applicable_regions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of affected regions
    business_processes_affected: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of affected processes

    # Impact assessment
    conflict_severity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical
    business_impact: Mapped[str] = mapped_column(Text, nullable=True)
    compliance_risk: Mapped[str] = mapped_column(Text, nullable=True)
    operational_complexity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high

    # Resolution approach
    resolution_strategy: Mapped[str] = mapped_column(String(100), nullable=False)  # harmonization, localization, exemption, technology_solution
    resolution_details: Mapped[str] = mapped_column(Text, nullable=True)
    implementation_plan: Mapped[str] = mapped_column(Text, nullable=True)

    # Resolution status
    resolution_status: Mapped[str] = mapped_column(String(50), default="identified")  # identified, analyzing, resolved, implemented, monitored
    resolution_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    effectiveness_rating: Mapped[int] = mapped_column(Integer, nullable=True)  # 1-5 effectiveness rating

    # Governance
    identified_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    resolved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    strategy = relationship("ComplianceStrategy", back_populates="conflicts")
    identifier = relationship("User", foreign_keys=[identified_by])
    resolver = relationship("User", foreign_keys=[resolved_by])
    approver = relationship("User", foreign_keys=[approved_by])


class ComplianceRoadmap(Base):
    """3-year strategic compliance roadmap with milestones and resource allocation."""

    __tablename__ = "compliance_roadmaps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    strategy_id: Mapped[int] = mapped_column(ForeignKey("compliance_strategies.id"), nullable=False)

    # Roadmap details
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    timeframe_years: Mapped[int] = mapped_column(Integer, default=3)
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Strategic phases
    phase_1_objectives: Mapped[str] = mapped_column(Text, nullable=True)  # Year 1 objectives
    phase_2_objectives: Mapped[str] = mapped_column(Text, nullable=True)  # Year 2 objectives
    phase_3_objectives: Mapped[str] = mapped_column(Text, nullable=True)  # Year 3 objectives

    # Resource allocation
    total_budget: Mapped[float] = mapped_column(Float, default=0.0)
    budget_breakdown: Mapped[str] = mapped_column(Text, nullable=True)  # JSON breakdown by category/year
    fte_requirements: Mapped[str] = mapped_column(Text, nullable=True)  # JSON FTE requirements by phase
    technology_investments: Mapped[str] = mapped_column(Text, nullable=True)  # JSON technology roadmap

    # Key milestones
    milestones: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of major milestones

    # Success metrics
    kpis: Mapped[str] = mapped_column(Text, nullable=True)  # JSON key performance indicators
    success_criteria: Mapped[str] = mapped_column(Text, nullable=True)  # JSON success measurement criteria

    # Risk considerations
    roadmap_risks: Mapped[str] = mapped_column(Text, nullable=True)  # JSON potential risks to roadmap execution
    mitigation_strategies: Mapped[str] = mapped_column(Text, nullable=True)  # JSON risk mitigation approaches

    # Status and tracking
    status: Mapped[str] = mapped_column(String(50), default="planning")  # planning, active, completed, cancelled
    progress_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    last_progress_update: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Governance
    roadmap_owner: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    steering_committee: Mapped[str] = mapped_column(Text, nullable=True)  # JSON committee members

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    strategy = relationship("ComplianceStrategy", back_populates="roadmaps")
    owner = relationship("User", backref="compliance_roadmaps")
    milestones_list = relationship("RoadmapMilestone", back_populates="roadmap", cascade="all, delete-orphan")


class RoadmapMilestone(Base):
    """Individual milestones within a compliance roadmap."""

    __tablename__ = "roadmap_milestones"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    roadmap_id: Mapped[int] = mapped_column(ForeignKey("compliance_roadmaps.id"), nullable=False)

    # Milestone details
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    milestone_type: Mapped[str] = mapped_column(String(50), nullable=False)  # implementation, assessment, certification, training, etc.

    # Timeline
    planned_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    actual_completion_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Dependencies and prerequisites
    prerequisites: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of prerequisite milestones
    dependencies: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of dependent milestones

    # Resource requirements
    budget_allocated: Mapped[float] = mapped_column(Float, default=0.0)
    fte_allocated: Mapped[float] = mapped_column(Float, default=0.0)  # FTE months
    resources_required: Mapped[str] = mapped_column(Text, nullable=True)  # JSON resource requirements

    # Success criteria
    success_criteria: Mapped[str] = mapped_column(Text, nullable=True)  # JSON success measurement criteria
    deliverables: Mapped[str] = mapped_column(Text, nullable=True)  # JSON expected deliverables

    # Status and tracking
    status: Mapped[str] = mapped_column(String(50), default="planned")  # planned, in_progress, completed, delayed, cancelled
    progress_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    delay_reason: Mapped[str] = mapped_column(Text, nullable=True)

    # Governance
    responsible_party: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    roadmap = relationship("ComplianceRoadmap", back_populates="milestones_list")
    responsible_user = relationship("User", backref="roadmap_milestones")


class ComplianceArchitecture(Base):
    """Enterprise compliance architecture supporting 10,000+ employees across multiple locations."""

    __tablename__ = "compliance_architectures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    strategy_id: Mapped[int] = mapped_column(ForeignKey("compliance_strategies.id"), nullable=False)

    # Architecture overview
    architecture_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    strategy_name: Mapped[str] = mapped_column(String(255), nullable=True)

    # Scale and scope
    total_employees: Mapped[int] = mapped_column(Integer, nullable=True)
    number_of_locations: Mapped[int] = mapped_column(Integer, default=1)
    geographic_distribution: Mapped[str] = mapped_column(Text, nullable=True)  # JSON geographic breakdown

    # Technology stack
    core_platform: Mapped[str] = mapped_column(String(100), nullable=True)  # Primary GRC platform
    integration_platforms: Mapped[str] = mapped_column(Text, nullable=True)  # JSON integrated systems
    automation_tools: Mapped[str] = mapped_column(Text, nullable=True)  # JSON automation technologies

    # Organizational structure
    compliance_team_structure: Mapped[str] = mapped_column(Text, nullable=True)  # JSON team organization
    governance_committees: Mapped[str] = mapped_column(Text, nullable=True)  # JSON governance bodies
    reporting_hierarchy: Mapped[str] = mapped_column(Text, nullable=True)  # JSON reporting structure

    # Control framework
    control_families: Mapped[str] = mapped_column(Text, nullable=True)  # JSON control family definitions
    control_mappings: Mapped[str] = mapped_column(Text, nullable=True)  # JSON framework to control mappings
    automation_coverage: Mapped[str] = mapped_column(Text, nullable=True)  # JSON automation coverage by control

    # Data architecture
    data_collection_methods: Mapped[str] = mapped_column(Text, nullable=True)  # JSON data collection approaches
    data_storage_strategy: Mapped[str] = mapped_column(String(100), nullable=True)
    reporting_capabilities: Mapped[str] = mapped_column(Text, nullable=True)  # JSON reporting features

    # Scalability considerations
    performance_requirements: Mapped[str] = mapped_column(Text, nullable=True)  # JSON performance metrics
    high_availability_requirements: Mapped[str] = mapped_column(Text, nullable=True)  # JSON HA requirements
    disaster_recovery_plan: Mapped[str] = mapped_column(Text, nullable=True)

    # Security architecture
    access_control_model: Mapped[str] = mapped_column(String(100), default="role_based")
    encryption_standards: Mapped[str] = mapped_column(Text, nullable=True)  # JSON encryption requirements
    audit_trail_requirements: Mapped[str] = mapped_column(Text, nullable=True)  # JSON audit capabilities

    # Implementation roadmap
    implementation_phases: Mapped[str] = mapped_column(Text, nullable=True)  # JSON implementation phases
    migration_strategy: Mapped[str] = mapped_column(Text, nullable=True)
    change_management_approach: Mapped[str] = mapped_column(Text, nullable=True)

    # Cost and ROI
    total_cost_estimate: Mapped[float] = mapped_column(Float, default=0.0)
    cost_breakdown: Mapped[str] = mapped_column(Text, nullable=True)  # JSON cost categories
    roi_projections: Mapped[str] = mapped_column(Text, nullable=True)  # JSON ROI analysis

    # Status and governance
    status: Mapped[str] = mapped_column(String(50), default="design")  # design, development, testing, production, retired
    version: Mapped[str] = mapped_column(String(20), default="1.0")
    architecture_owner: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    strategy = relationship("ComplianceStrategy", back_populates="architectures")
    owner = relationship("User", backref="compliance_architectures")


class ControlMapping(Base):
    """Multi-framework control mapping system for integrated compliance management."""

    __tablename__ = "control_mappings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    # Control definition
    control_id: Mapped[str] = mapped_column(String(100), nullable=False)  # Unique control identifier
    control_name: Mapped[str] = mapped_column(String(255), nullable=False)
    control_description: Mapped[str] = mapped_column(Text, nullable=True)

    # Framework mappings
    framework_mappings: Mapped[str] = mapped_column(Text, nullable=True)  # JSON mapping to different frameworks

    # Control attributes
    control_family: Mapped[str] = mapped_column(String(100), nullable=True)
    control_type: Mapped[str] = mapped_column(String(50), nullable=True)  # preventive, detective, corrective
    automation_potential: Mapped[str] = mapped_column(String(20), default="manual")  # manual, semi-automated, automated

    # Implementation details
    implementation_guidance: Mapped[str] = mapped_column(Text, nullable=True)
    testing_procedures: Mapped[str] = mapped_column(Text, nullable=True)
    evidence_requirements: Mapped[str] = mapped_column(Text, nullable=True)

    # Risk and impact
    risk_reduction_potential: Mapped[int] = mapped_column(Integer, default=3)  # 1-5 scale
    implementation_complexity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high
    resource_requirements: Mapped[str] = mapped_column(Text, nullable=True)  # JSON resource needs

    # Status and governance
    status: Mapped[str] = mapped_column(String(50), default="active")  # active, deprecated, retired
    version: Mapped[str] = mapped_column(String(20), default="1.0")
    last_reviewed: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships and ownership
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    approved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    approver = relationship("User", foreign_keys=[approved_by])


# Security Event Analysis Models

class LogAnalysis(Base):
    """Advanced log analysis with interpretation methodology for security events."""

    __tablename__ = "log_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    analysis_type: Mapped[str] = mapped_column(String(50), nullable=False)  # authentication, file_access, network_activity, system_events

    # Analysis scope
    log_sources: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of source IDs
    time_range_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    time_range_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    # Analysis methodology
    methodology: Mapped[str] = mapped_column(Text, nullable=False)  # Analysis approach and techniques
    interpretation_rules: Mapped[str] = mapped_column(Text, nullable=True)  # JSON rules for interpretation

    # Findings
    total_logs_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    suspicious_events: Mapped[int] = mapped_column(Integer, default=0)
    critical_events: Mapped[int] = mapped_column(Integer, default=0)
    anomalies_detected: Mapped[int] = mapped_column(Integer, default=0)

    # Detailed results
    analysis_results: Mapped[str] = mapped_column(Text, nullable=True)  # JSON detailed findings
    key_findings: Mapped[str] = mapped_column(Text, nullable=True)
    recommendations: Mapped[str] = mapped_column(Text, nullable=True)

    # Status and metadata
    status: Mapped[str] = mapped_column(String(50), default="in_progress")  # in_progress, completed, reviewed
    performed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    analyst = relationship("User", foreign_keys=[performed_by])
    reviewer = relationship("User", foreign_keys=[reviewed_by])


class LogCorrelation(Base):
    """Log correlation analysis between multiple sources showing related security events."""

    __tablename__ = "log_correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    correlation_name: Mapped[str] = mapped_column(String(255), nullable=False)
    correlation_type: Mapped[str] = mapped_column(String(50), nullable=False)  # temporal, behavioral, attribution, network

    # Correlation parameters
    primary_log_id: Mapped[int] = mapped_column(ForeignKey("collected_logs.id"), nullable=False)
    correlated_logs: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of related log IDs
    correlation_strength: Mapped[float] = mapped_column(Float, default=0.0)  # 0-1 correlation confidence

    # Analysis details
    correlation_method: Mapped[str] = mapped_column(String(100), nullable=False)  # time_window, ip_address, user_account, etc.
    time_window_seconds: Mapped[int] = mapped_column(Integer, default=300)  # Correlation time window
    common_attributes: Mapped[str] = mapped_column(Text, nullable=True)  # JSON shared attributes

    # Findings
    correlation_summary: Mapped[str] = mapped_column(Text, nullable=True)
    security_implications: Mapped[str] = mapped_column(Text, nullable=True)
    risk_assessment: Mapped[str] = mapped_column(String(20), default="low")  # low, medium, high, critical

    # Status
    validated: Mapped[bool] = mapped_column(Boolean, default=False)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    primary_log = relationship("CollectedLog")


class IncidentDetection(Base):
    """Complete incident detection scenario with timeline, correlation, and conclusions."""

    __tablename__ = "incident_detections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_title: Mapped[str] = mapped_column(String(255), nullable=False)
    detection_scenario: Mapped[str] = mapped_column(String(100), nullable=False)  # brute_force, lateral_movement, data_exfil, etc.

    # Incident timeline
    detection_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    incident_start: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    incident_end: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Event sequence
    event_timeline: Mapped[str] = mapped_column(Text, nullable=True)  # JSON timeline of events
    key_indicators: Mapped[str] = mapped_column(Text, nullable=True)  # JSON key indicators identified

    # Correlation analysis
    log_correlations: Mapped[str] = mapped_column(Text, nullable=True)  # JSON correlation findings
    attack_vector: Mapped[str] = mapped_column(String(100), nullable=True)
    attacker_profile: Mapped[str] = mapped_column(Text, nullable=True)

    # Impact assessment
    affected_systems: Mapped[str] = mapped_column(Text, nullable=True)  # JSON affected systems
    potential_impact: Mapped[str] = mapped_column(String(20), default="low")  # low, medium, high, critical
    containment_status: Mapped[str] = mapped_column(String(50), default="detected")  # detected, contained, eradicated, recovered

    # Conclusions and response
    root_cause_analysis: Mapped[str] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[str] = mapped_column(Text, nullable=True)
    prevention_recommendations: Mapped[str] = mapped_column(Text, nullable=True)

    # Documentation
    investigation_methodology: Mapped[str] = mapped_column(Text, nullable=True)
    evidence_chain: Mapped[str] = mapped_column(Text, nullable=True)  # JSON evidence documentation

    # Governance
    detected_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    assigned_to: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="detected")  # detected, investigating, contained, resolved

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    detector = relationship("User", foreign_keys=[detected_by])
    assignee = relationship("User", foreign_keys=[assigned_to])


class AlertTriage(Base):
    """Alert triage process with severity assessment, false positive identification, and escalation."""

    __tablename__ = "alert_triages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id"), nullable=False)

    # Triage assessment
    triage_priority: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical
    assessed_severity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical
    confidence_level: Mapped[int] = mapped_column(Integer, default=50)  # 0-100 confidence in assessment

    # False positive analysis
    false_positive_probability: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    false_positive_reason: Mapped[str] = mapped_column(Text, nullable=True)
    validation_method: Mapped[str] = mapped_column(String(100), nullable=True)  # manual_review, automated_check, correlation_analysis

    # Escalation criteria
    escalation_required: Mapped[bool] = mapped_column(Boolean, default=False)
    escalation_reason: Mapped[str] = mapped_column(Text, nullable=True)
    escalation_level: Mapped[str] = mapped_column(String(50), nullable=True)  # security_team, management, executive

    # Investigation details
    investigation_steps: Mapped[str] = mapped_column(Text, nullable=True)  # JSON investigation steps taken
    additional_context: Mapped[str] = mapped_column(Text, nullable=True)
    related_alerts: Mapped[str] = mapped_column(Text, nullable=True)  # JSON related alert IDs

    # Resolution
    triage_conclusion: Mapped[str] = mapped_column(String(100), nullable=True)  # confirmed_threat, false_positive, benign_activity, etc.
    action_taken: Mapped[str] = mapped_column(Text, nullable=True)
    follow_up_required: Mapped[bool] = mapped_column(Boolean, default=False)

    # Governance
    triaged_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    triage_duration_minutes: Mapped[int] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    alert = relationship("Alert")
    triage_analyst = relationship("User", foreign_keys=[triaged_by])
    reviewer = relationship("User", foreign_keys=[reviewed_by])


class AnalysisDocumentation(Base):
    """Comprehensive analysis documentation with annotated log excerpts and investigation methodology."""

    __tablename__ = "analysis_documentation"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    documentation_type: Mapped[str] = mapped_column(String(50), nullable=False)  # log_analysis, correlation, incident_detection, triage

    # Documentation scope
    analysis_period_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    analysis_period_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    systems_analyzed: Mapped[str] = mapped_column(Text, nullable=True)  # JSON system list

    # Methodology documentation
    investigation_methodology: Mapped[str] = mapped_column(Text, nullable=False)
    tools_used: Mapped[str] = mapped_column(Text, nullable=True)  # JSON tools and versions
    data_sources: Mapped[str] = mapped_column(Text, nullable=True)  # JSON data sources used

    # Annotated log excerpts
    log_excerpts: Mapped[str] = mapped_column(Text, nullable=True)  # JSON annotated log samples
    interpretation_guide: Mapped[str] = mapped_column(Text, nullable=True)  # How to interpret the logs

    # Findings and analysis
    key_findings: Mapped[str] = mapped_column(Text, nullable=True)
    security_implications: Mapped[str] = mapped_column(Text, nullable=True)
    risk_assessment: Mapped[str] = mapped_column(Text, nullable=True)

    # Recommendations
    mitigation_recommendations: Mapped[str] = mapped_column(Text, nullable=True)
    monitoring_enhancements: Mapped[str] = mapped_column(Text, nullable=True)
    process_improvements: Mapped[str] = mapped_column(Text, nullable=True)

    # Quality assurance
    peer_review_status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, in_review, approved, rejected
    review_comments: Mapped[str] = mapped_column(Text, nullable=True)
    accuracy_confidence: Mapped[int] = mapped_column(Integer, default=50)  # 0-100

    # Governance
    documented_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    documenter = relationship("User", foreign_keys=[documented_by])
    reviewer = relationship("User", foreign_keys=[reviewed_by])
    approver = relationship("User", foreign_keys=[approved_by])


class TimelineEvent(Base):
    """Represents individual events in a security timeline analysis."""

    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timeline_id: Mapped[int] = mapped_column(ForeignKey("security_timelines.id"), nullable=False)

    # Event details
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)  # log_entry, alert, system_event, user_action
    source_system: Mapped[str] = mapped_column(String(100), nullable=False)  # macOS, Parrot OS, Windows, etc.
    source_component: Mapped[str] = mapped_column(String(100), nullable=True)  # auth.log, syslog, wazuh, etc.

    # Event content
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    raw_data: Mapped[str] = mapped_column(Text, nullable=True)  # Original log entry or event data

    # Analysis and classification
    severity: Mapped[str] = mapped_column(String(20), default="info")  # critical, high, medium, low, info
    category: Mapped[str] = mapped_column(String(50), nullable=True)  # authentication, file_access, network, system, etc.
    tags: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of tags

    # Relationships and correlations
    related_events: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of related event IDs
    correlation_id: Mapped[str] = mapped_column(String(100), nullable=True)  # Group related events

    # Analysis notes
    analysis_notes: Mapped[str] = mapped_column(Text, nullable=True)
    investigator_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    timeline = relationship("SecurityTimeline", back_populates="events")
    investigator = relationship("User", backref="timeline_events")


class SecurityTimeline(Base):
    """Represents a comprehensive security timeline analysis incorporating multiple log sources."""

    __tablename__ = "security_timelines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Timeline scope
    analysis_period_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    analysis_period_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=True)

    # Source systems included
    source_systems: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of systems (macOS, Parrot OS, etc.)
    log_sources: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of specific log sources

    # Timeline analysis
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    critical_events: Mapped[int] = mapped_column(Integer, default=0)
    high_events: Mapped[int] = mapped_column(Integer, default=0)
    medium_events: Mapped[int] = mapped_column(Integer, default=0)
    low_events: Mapped[int] = mapped_column(Integer, default=0)

    # Analysis results
    key_findings: Mapped[str] = mapped_column(Text, nullable=True)
    attack_sequence: Mapped[str] = mapped_column(Text, nullable=True)  # JSON timeline of attack progression
    security_implications: Mapped[str] = mapped_column(Text, nullable=True)

    # Timeline visualization
    timeline_data: Mapped[str] = mapped_column(Text, nullable=True)  # JSON data for timeline visualization

    # Status and governance
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft, analyzing, completed, reviewed
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Relationships
    events = relationship("TimelineEvent", back_populates="timeline", cascade="all, delete-orphan")
    incident = relationship("Incident", backref="security_timelines")
    creator = relationship("User", foreign_keys=[created_by])
    reviewer = relationship("User", foreign_keys=[reviewed_by])

    def add_event(self, timestamp: datetime, event_type: str, source_system: str, title: str,
                  description: str, severity: str = "info", category: str = None,
                  source_component: str = None, raw_data: str = None, tags: list = None,
                  investigator_id: int = None):
        """Add an event to the timeline."""
        import json

        event = TimelineEvent(
            timeline_id=self.id,
            timestamp=timestamp,
            event_type=event_type,
            source_system=source_system,
            source_component=source_component,
            title=title,
            description=description,
            raw_data=raw_data,
            severity=severity,
            category=category,
            tags=json.dumps(tags) if tags else None,
            investigator_id=investigator_id
        )

        self.events.append(event)
        self.total_events += 1

        # Update severity counts
        if severity == "critical":
            self.critical_events += 1
        elif severity == "high":
            self.high_events += 1
        elif severity == "medium":
            self.medium_events += 1
        elif severity == "low":
            self.low_events += 1

    def generate_attack_sequence(self):
        """Generate a chronological sequence of attack events."""
        import json

        # Sort events by timestamp
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)

        attack_sequence = []
        for event in sorted_events:
            attack_sequence.append({
                "timestamp": event.timestamp.isoformat(),
                "event_type": event.event_type,
                "source_system": event.source_system,
                "title": event.title,
                "severity": event.severity,
                "description": event.description
            })

        self.attack_sequence = json.dumps(attack_sequence, indent=2)
        return attack_sequence

    def get_timeline_visualization_data(self):
        """Generate data for timeline visualization."""
        import json

        visualization_data = {
            "title": self.title,
            "period": {
                "start": self.analysis_period_start.isoformat(),
                "end": self.analysis_period_end.isoformat()
            },
            "events": []
        }

        for event in sorted(self.events, key=lambda e: e.timestamp):
            event_data = {
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "type": event.event_type,
                "system": event.source_system,
                "title": event.title,
                "description": event.description,
                "severity": event.severity,
                "category": event.category
            }
            visualization_data["events"].append(event_data)

        self.timeline_data = json.dumps(visualization_data, indent=2)
        return visualization_data

class LiveFileEvidence(Base):
    """File system evidence collected from Parrot OS systems"""
    __tablename__ = "live_file_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # File details
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    permissions: Mapped[str] = mapped_column(String(10), nullable=True)
    owner: Mapped[str] = mapped_column(String(100), nullable=True)
    group: Mapped[str] = mapped_column(String(100), nullable=True)
    size: Mapped[int] = mapped_column(Integer, nullable=True)
    mtime: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    exists: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)

    # Collection metadata
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class MemoryAnalysis(Base):
    """Memory analysis results from Volatility"""
    __tablename__ = "memory_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Analysis details
    analysis_type: Mapped[str] = mapped_column(String(50), nullable=False)  # volatility_basic, volatility_full, etc.
    profile: Mapped[str] = mapped_column(String(100), nullable=True)  # Linux, Win7SP1x64, etc.

    # Analysis results
    total_processes: Mapped[int] = mapped_column(Integer, default=0)
    suspicious_processes: Mapped[int] = mapped_column(Integer, default=0)
    network_connections: Mapped[int] = mapped_column(Integer, default=0)
    registry_hives: Mapped[int] = mapped_column(Integer, default=0)  # Windows only

    # Detailed analysis output (JSON)
    analysis_output: Mapped[str] = mapped_column(Text, nullable=True)

    # Metadata
    analyzed_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class DiskImage(Base):
    """Forensic disk images created from Parrot OS systems"""
    __tablename__ = "disk_images"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    system_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Imaging details
    source_device: Mapped[str] = mapped_column(String(255), nullable=False)  # /dev/sda, /dev/sdb, etc.
    image_path: Mapped[str] = mapped_column(String(512), nullable=False)  # Path to the created image
    image_size: Mapped[int] = mapped_column(Integer, nullable=True)  # Size in bytes
    hash_value: Mapped[str] = mapped_column(String(128), nullable=True)  # SHA256 hash
    imaging_tool: Mapped[str] = mapped_column(String(50), nullable=True)  # dc3dd, dd, etc.

    # Case information
    case_number: Mapped[str] = mapped_column(String(100), nullable=True)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))    




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
    # workflow = relationship("ComplianceWorkflow", backref="decision_points")


# Process Integration & Optimization Models

class BusinessProcess(Base):
    """Complex business process mapping for compliance integration."""

    __tablename__ = "business_processes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    process_type: Mapped[str] = mapped_column(String(100), nullable=False)  # operational, compliance, financial, etc.

    # Process structure
    process_flow: Mapped[str] = mapped_column(Text, nullable=True)  # JSON process flow definition
    subprocesses: Mapped[str] = mapped_column(Text, nullable=True)  # JSON subprocess hierarchy
    dependencies: Mapped[str] = mapped_column(Text, nullable=True)  # JSON dependency mapping

    # Compliance integration
    compliance_frameworks: Mapped[str] = mapped_column(Text, nullable=True)  # JSON applicable frameworks
    control_mappings: Mapped[str] = mapped_column(Text, nullable=True)  # JSON control to process mappings
    risk_assessments: Mapped[str] = mapped_column(Text, nullable=True)  # JSON embedded risk assessments

    # Performance metrics
    baseline_efficiency: Mapped[float] = mapped_column(Float, default=0.0)  # Baseline efficiency percentage
    current_efficiency: Mapped[float] = mapped_column(Float, default=0.0)  # Current efficiency percentage
    target_efficiency: Mapped[float] = mapped_column(Float, default=0.0)  # Target efficiency (e.g., 30% improvement)

    # Process metadata
    owner: Mapped[str] = mapped_column(String(255), nullable=True)
    department: Mapped[str] = mapped_column(String(100), nullable=True)
    criticality_level: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical

    # Status and versioning
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft, active, deprecated
    version: Mapped[str] = mapped_column(String(20), default="1.0")

    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    approved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    approver = relationship("User", foreign_keys=[approved_by])
    optimizations = relationship("ProcessOptimization", back_populates="process", cascade="all, delete-orphan")


class ProcessOptimization(Base):
    """Process optimization algorithms and results for efficiency improvement."""

    __tablename__ = "process_optimizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    process_id: Mapped[int] = mapped_column(ForeignKey("business_processes.id"), nullable=False)

    # Optimization details
    optimization_name: Mapped[str] = mapped_column(String(255), nullable=False)
    optimization_type: Mapped[str] = mapped_column(String(100), nullable=False)  # automation, streamlining, parallelization, elimination
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Algorithm and methodology
    algorithm_used: Mapped[str] = mapped_column(String(100), nullable=True)  # lean_six_sigma, theory_of_constraints, value_stream_mapping
    methodology_documentation: Mapped[str] = mapped_column(Text, nullable=True)  # JSON methodology details

    # Before/after metrics
    baseline_metrics: Mapped[str] = mapped_column(Text, nullable=True)  # JSON baseline measurements
    optimized_metrics: Mapped[str] = mapped_column(Text, nullable=True)  # JSON post-optimization measurements

    # Efficiency improvement
    efficiency_improvement_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    time_savings_hours: Mapped[float] = mapped_column(Float, default=0.0)
    cost_savings_amount: Mapped[float] = mapped_column(Float, default=0.0)

    # Implementation details
    implementation_steps: Mapped[str] = mapped_column(Text, nullable=True)  # JSON implementation plan
    required_resources: Mapped[str] = mapped_column(Text, nullable=True)  # JSON resource requirements
    timeline_days: Mapped[int] = mapped_column(Integer, default=0)

    # Validation and results
    validation_results: Mapped[str] = mapped_column(Text, nullable=True)  # JSON validation outcomes
    success_criteria: Mapped[str] = mapped_column(Text, nullable=True)  # JSON success metrics

    # Status tracking
    status: Mapped[str] = mapped_column(String(50), default="planned")  # planned, implementing, completed, validated
    implementation_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    validation_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Governance
    performed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    process = relationship("BusinessProcess", back_populates="optimizations")
    performer = relationship("User", foreign_keys=[performed_by])
    reviewer = relationship("User", foreign_keys=[reviewed_by])
    validation_procedures = relationship("ValidationProcedure", back_populates="optimization")


class DataSynchronization(Base):
    """Real-time data synchronization across enterprise systems."""

    __tablename__ = "data_synchronizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sync_name: Mapped[str] = mapped_column(String(255), nullable=False)
    sync_type: Mapped[str] = mapped_column(String(50), nullable=False)  # full_sync, incremental, real_time

    # Source and target systems
    source_system: Mapped[str] = mapped_column(String(255), nullable=False)
    target_system: Mapped[str] = mapped_column(String(255), nullable=False)
    source_endpoint: Mapped[str] = mapped_column(String(500), nullable=True)  # API endpoint or connection string
    target_endpoint: Mapped[str] = mapped_column(String(500), nullable=True)

    # Data mapping
    data_mapping: Mapped[str] = mapped_column(Text, nullable=True)  # JSON field mappings
    transformation_rules: Mapped[str] = mapped_column(Text, nullable=True)  # JSON transformation logic

    # Synchronization settings
    sync_frequency: Mapped[str] = mapped_column(String(50), default="real_time")  # real_time, hourly, daily, weekly
    batch_size: Mapped[int] = mapped_column(Integer, default=1000)
    conflict_resolution: Mapped[str] = mapped_column(String(50), default="last_write_wins")  # last_write_wins, manual, source_priority

    # Authentication and security
    auth_method: Mapped[str] = mapped_column(String(50), nullable=True)  # api_key, oauth, certificate
    encryption_enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # Performance and monitoring
    last_sync_time: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    sync_duration_seconds: Mapped[int] = mapped_column(Integer, default=0)
    records_processed: Mapped[int] = mapped_column(Integer, default=0)
    success_rate: Mapped[float] = mapped_column(Float, default=0.0)

    # Error handling
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error_message: Mapped[str] = mapped_column(Text, nullable=True)
    retry_attempts: Mapped[int] = mapped_column(Integer, default=3)

    # Status
    status: Mapped[str] = mapped_column(String(50), default="active")  # active, paused, error, disabled

    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", backref="data_synchronizations")


class EfficiencyMetrics(Base):
    """Efficiency metrics tracking for process optimization."""

    __tablename__ = "efficiency_metrics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    process_id: Mapped[int] = mapped_column(ForeignKey("business_processes.id"), nullable=True)
    optimization_id: Mapped[int] = mapped_column(ForeignKey("process_optimizations.id"), nullable=True)

    # Metric details
    metric_name: Mapped[str] = mapped_column(String(255), nullable=False)
    metric_type: Mapped[str] = mapped_column(String(100), nullable=False)  # time, cost, quality, compliance
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Baseline and current values
    baseline_value: Mapped[float] = mapped_column(Float, default=0.0)
    current_value: Mapped[float] = mapped_column(Float, default=0.0)
    target_value: Mapped[float] = mapped_column(Float, default=0.0)

    # Improvement tracking
    improvement_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    improvement_trend: Mapped[str] = mapped_column(String(50), default="stable")  # improving, declining, stable

    # Measurement details
    unit_of_measure: Mapped[str] = mapped_column(String(50), nullable=True)  # hours, dollars, percentage, count
    measurement_frequency: Mapped[str] = mapped_column(String(50), default="monthly")  # daily, weekly, monthly, quarterly
    calculation_method: Mapped[str] = mapped_column(Text, nullable=True)

    # Validation
    last_measured: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    measured_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    validation_status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, validated, disputed

    # Historical tracking
    historical_data: Mapped[str] = mapped_column(Text, nullable=True)  # JSON time series data

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    process = relationship("BusinessProcess", backref="efficiency_metrics")
    optimization = relationship("ProcessOptimization", backref="efficiency_metrics")
    measurer = relationship("User", backref="efficiency_measurements")


class OptimizationMethodology(Base):
    """Documented process optimization methodology."""

    __tablename__ = "optimization_methodologies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    methodology_type: Mapped[str] = mapped_column(String(100), nullable=False)  # lean, six_sigma, theory_of_constraints, custom

    # Methodology documentation
    description: Mapped[str] = mapped_column(Text, nullable=False)
    objectives: Mapped[str] = mapped_column(Text, nullable=True)  # JSON methodology objectives
    scope: Mapped[str] = mapped_column(Text, nullable=True)  # JSON applicability scope

    # Process steps
    methodology_steps: Mapped[str] = mapped_column(Text, nullable=True)  # JSON step-by-step process
    tools_required: Mapped[str] = mapped_column(Text, nullable=True)  # JSON required tools and techniques
    success_criteria: Mapped[str] = mapped_column(Text, nullable=True)  # JSON success measurement criteria

    # Framework alignment
    compliance_frameworks: Mapped[str] = mapped_column(Text, nullable=True)  # JSON supported frameworks
    industry_standards: Mapped[str] = mapped_column(Text, nullable=True)  # JSON aligned standards

    # Expected outcomes
    expected_efficiency_gain: Mapped[float] = mapped_column(Float, default=0.0)  # Expected percentage improvement
    typical_timeline: Mapped[str] = mapped_column(String(100), nullable=True)  # Typical implementation timeline
    resource_requirements: Mapped[str] = mapped_column(Text, nullable=True)  # JSON resource needs

    # Validation procedures
    validation_methods: Mapped[str] = mapped_column(Text, nullable=True)  # JSON validation approaches
    measurement_procedures: Mapped[str] = mapped_column(Text, nullable=True)  # JSON measurement methods

    # Status and approval
    status: Mapped[str] = mapped_column(String(50), default="draft")  # draft, approved, deprecated
    version: Mapped[str] = mapped_column(String(20), default="1.0")

    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    approved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    approver = relationship("User", foreign_keys=[approved_by])


class BaselineMeasurement(Base):
    """Baseline measurements for process optimization validation."""

    __tablename__ = "baseline_measurements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    process_id: Mapped[int] = mapped_column(ForeignKey("business_processes.id"), nullable=False)
    methodology_id: Mapped[int] = mapped_column(ForeignKey("optimization_methodologies.id"), nullable=True)

    # Measurement details
    measurement_name: Mapped[str] = mapped_column(String(255), nullable=False)
    measurement_type: Mapped[str] = mapped_column(String(100), nullable=False)  # performance, efficiency, compliance, cost
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Baseline data
    baseline_value: Mapped[float] = mapped_column(Float, default=0.0)
    baseline_unit: Mapped[str] = mapped_column(String(50), nullable=True)  # hours, dollars, percentage, count
    measurement_date: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Measurement context
    measurement_conditions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON measurement conditions
    data_sources: Mapped[str] = mapped_column(Text, nullable=True)  # JSON data source details
    sample_size: Mapped[int] = mapped_column(Integer, nullable=True)

    # Statistical validation
    confidence_level: Mapped[float] = mapped_column(Float, default=0.95)  # Statistical confidence level
    margin_of_error: Mapped[float] = mapped_column(Float, default=0.0)
    standard_deviation: Mapped[float] = mapped_column(Float, nullable=True)

    # Validation status
    validation_status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, validated, disputed
    validation_notes: Mapped[str] = mapped_column(Text, nullable=True)

    # Governance
    measured_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    process = relationship("BusinessProcess", backref="baseline_measurements")
    methodology = relationship("OptimizationMethodology", backref="baseline_measurements")
    measurer = relationship("User", foreign_keys=[measured_by])
    reviewer = relationship("User", foreign_keys=[reviewed_by])


class ValidationProcedure(Base):
    """Validation procedures for process optimization results."""

    __tablename__ = "validation_procedures"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    optimization_id: Mapped[int] = mapped_column(ForeignKey("process_optimizations.id"), nullable=False)

    # Procedure details
    procedure_name: Mapped[str] = mapped_column(String(255), nullable=False)
    procedure_type: Mapped[str] = mapped_column(String(100), nullable=False)  # statistical, comparative, expert_review, automated
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Validation methodology
    validation_steps: Mapped[str] = mapped_column(Text, nullable=True)  # JSON step-by-step validation process
    acceptance_criteria: Mapped[str] = mapped_column(Text, nullable=True)  # JSON acceptance criteria
    statistical_methods: Mapped[str] = mapped_column(Text, nullable=True)  # JSON statistical validation methods

    # Data requirements
    required_data_points: Mapped[str] = mapped_column(Text, nullable=True)  # JSON required data
    sampling_methodology: Mapped[str] = mapped_column(Text, nullable=True)  # JSON sampling approach
    measurement_frequency: Mapped[str] = mapped_column(String(50), default="monthly")  # daily, weekly, monthly, quarterly

    # Validation results
    validation_status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, in_progress, completed, failed
    validation_result: Mapped[str] = mapped_column(String(50), nullable=True)  # passed, failed, inconclusive
    validation_score: Mapped[float] = mapped_column(Float, nullable=True)  # 0-100 validation confidence score

    # Detailed findings
    findings_summary: Mapped[str] = mapped_column(Text, nullable=True)
    recommendations: Mapped[str] = mapped_column(Text, nullable=True)
    limitations: Mapped[str] = mapped_column(Text, nullable=True)  # JSON validation limitations

    # Timeline
    planned_completion: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    actual_completion: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Governance
    performed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    optimization = relationship("ProcessOptimization", back_populates="validation_procedures")
    performer = relationship("User", foreign_keys=[performed_by])
    reviewer = relationship("User", foreign_keys=[reviewed_by])


# Advanced Auditing Models

class AdvancedAudit(Base):
    """Advanced multi-site compliance audit with virtual and on-site components."""

    __tablename__ = "advanced_audits"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_title: Mapped[str] = mapped_column(String(255), nullable=False)
    audit_type: Mapped[str] = mapped_column(String(50), nullable=False)  # compliance, operational, financial, integrated
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Audit scope and coverage
    scope_frameworks: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of compliance frameworks
    audit_sites: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array of audit sites/locations
    audit_components: Mapped[str] = mapped_column(Text, nullable=True)  # JSON virtual and on-site components

    # Timeline and scheduling
    planned_start_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    planned_end_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    actual_start_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    actual_end_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Audit team and resources
    lead_auditor_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    audit_budget: Mapped[float] = mapped_column(Float, default=0.0)
    resource_allocation: Mapped[str] = mapped_column(Text, nullable=True)  # JSON resource requirements

    # Audit methodology
    audit_methodology: Mapped[str] = mapped_column(Text, nullable=True)  # JSON audit approach and techniques
    risk_assessment_approach: Mapped[str] = mapped_column(String(100), nullable=True)
    sampling_methodology: Mapped[str] = mapped_column(Text, nullable=True)  # JSON sampling strategy

    # Progress and status
    status: Mapped[str] = mapped_column(String(50), default="planned")  # planned, in_progress, completed, cancelled
    progress_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    current_phase: Mapped[str] = mapped_column(String(100), nullable=True)  # planning, fieldwork, analysis, reporting

    # Findings and results
    total_findings: Mapped[int] = mapped_column(Integer, default=0)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0)
    high_findings: Mapped[int] = mapped_column(Integer, default=0)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0)
    low_findings: Mapped[int] = mapped_column(Integer, default=0)

    # Compliance scores
    overall_compliance_score: Mapped[float] = mapped_column(Float, default=0.0)
    framework_scores: Mapped[str] = mapped_column(Text, nullable=True)  # JSON scores by framework

    # Documentation
    audit_plan_document: Mapped[str] = mapped_column(Text, nullable=True)  # JSON audit plan details
    working_papers: Mapped[str] = mapped_column(Text, nullable=True)  # JSON working paper references
    final_report: Mapped[str] = mapped_column(Text, nullable=True)  # JSON final audit report

    # Governance
    approved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    lead_auditor = relationship("User", foreign_keys=[lead_auditor_id])
    approver = relationship("User", foreign_keys=[approved_by])
    reviewer = relationship("User", foreign_keys=[reviewed_by])
    audit_teams = relationship("AuditTeam", back_populates="audit", cascade="all, delete-orphan")
    evidence_analyses = relationship("EvidenceAnalysis", back_populates="audit", cascade="all, delete-orphan")


class AuditTeam(Base):
    """Cross-functional audit team covering IT, operational, and financial compliance."""

    __tablename__ = "audit_teams"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("advanced_audits.id"), nullable=False)

    # Team member details
    team_member_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    role_in_audit: Mapped[str] = mapped_column(String(100), nullable=False)  # lead_auditor, it_auditor, financial_auditor, operational_auditor, specialist
    expertise_areas: Mapped[str] = mapped_column(Text, nullable=True)  # JSON areas of expertise
    certifications: Mapped[str] = mapped_column(Text, nullable=True)  # JSON relevant certifications

    # Assignment details
    assigned_sites: Mapped[str] = mapped_column(Text, nullable=True)  # JSON sites assigned to this team member
    time_allocation: Mapped[float] = mapped_column(Float, default=1.0)  # FTE allocation to this audit
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Performance and contribution
    tasks_completed: Mapped[int] = mapped_column(Integer, default=0)
    findings_contributed: Mapped[int] = mapped_column(Integer, default=0)
    quality_rating: Mapped[int] = mapped_column(Integer, nullable=True)  # 1-5 performance rating

    # Communication and collaboration
    collaboration_notes: Mapped[str] = mapped_column(Text, nullable=True)
    training_provided: Mapped[str] = mapped_column(Text, nullable=True)  # JSON training sessions provided

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    audit = relationship("AdvancedAudit", back_populates="audit_teams")
    team_member = relationship("User")


class EvidenceAnalysis(Base):
    """Advanced evidence analysis using data analytics tools and statistical methods."""

    __tablename__ = "evidence_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    audit_id: Mapped[int] = mapped_column(ForeignKey("advanced_audits.id"), nullable=True)  # Can be standalone or part of audit

    # Analysis details
    analysis_title: Mapped[str] = mapped_column(String(255), nullable=False)
    analysis_type: Mapped[str] = mapped_column(String(50), nullable=False)  # statistical, data_analytics, forensic, correlational
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Data sources and scope
    data_sources: Mapped[str] = mapped_column(Text, nullable=True)  # JSON data sources used
    analysis_scope: Mapped[str] = mapped_column(Text, nullable=True)  # JSON scope of analysis
    sample_size: Mapped[int] = mapped_column(Integer, nullable=True)
    time_period: Mapped[str] = mapped_column(String(100), nullable=True)  # Time period analyzed

    # Analytical methods
    statistical_methods: Mapped[str] = mapped_column(Text, nullable=True)  # JSON statistical techniques used
    data_analytics_tools: Mapped[str] = mapped_column(Text, nullable=True)  # JSON tools and algorithms
    machine_learning_models: Mapped[str] = mapped_column(Text, nullable=True)  # JSON ML models applied

    # Analysis parameters
    confidence_level: Mapped[float] = mapped_column(Float, default=0.95)  # Statistical confidence level
    significance_threshold: Mapped[float] = mapped_column(Float, default=0.05)  # Statistical significance threshold
    outlier_detection_method: Mapped[str] = mapped_column(String(100), nullable=True)

    # Results and findings
    key_findings: Mapped[str] = mapped_column(Text, nullable=True)  # JSON key analytical findings
    statistical_significance: Mapped[str] = mapped_column(Text, nullable=True)  # JSON statistical test results
    anomalies_detected: Mapped[int] = mapped_column(Integer, default=0)
    patterns_identified: Mapped[str] = mapped_column(Text, nullable=True)  # JSON patterns found

    # Data quality and validation
    data_quality_score: Mapped[float] = mapped_column(Float, nullable=True)  # 0-100 data quality assessment
    validation_methods: Mapped[str] = mapped_column(Text, nullable=True)  # JSON validation techniques
    data_integrity_checks: Mapped[str] = mapped_column(Text, nullable=True)  # JSON integrity verification results

    # Visualizations and reporting
    charts_generated: Mapped[str] = mapped_column(Text, nullable=True)  # JSON chart configurations
    statistical_outputs: Mapped[str] = mapped_column(Text, nullable=True)  # JSON statistical analysis outputs

    # Status and metadata
    status: Mapped[str] = mapped_column(String(50), default="pending")  # pending, in_progress, completed, validated
    performed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    reviewed_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    audit = relationship("AdvancedAudit", back_populates="evidence_analyses")
    analyst = relationship("User", foreign_keys=[performed_by])
    reviewer = relationship("User", foreign_keys=[reviewed_by])


class ComplianceAnalytics(Base):
    """Compliance analytics solution with predictive capabilities."""

    __tablename__ = "compliance_analytics"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    analytics_name: Mapped[str] = mapped_column(String(255), nullable=False)
    analytics_type: Mapped[str] = mapped_column(String(50), nullable=False)  # predictive, diagnostic, descriptive, prescriptive

    # Analytics scope
    frameworks_analyzed: Mapped[str] = mapped_column(Text, nullable=True)  # JSON compliance frameworks
    data_sources: Mapped[str] = mapped_column(Text, nullable=True)  # JSON data sources
    analysis_period: Mapped[str] = mapped_column(String(100), nullable=True)  # Time period for analysis

    # Predictive modeling
    prediction_target: Mapped[str] = mapped_column(String(255), nullable=True)  # What is being predicted
    prediction_horizon: Mapped[str] = mapped_column(String(50), nullable=True)  # short_term, medium_term, long_term
    model_type: Mapped[str] = mapped_column(String(100), nullable=True)  # regression, classification, time_series, anomaly_detection

    # Model performance
    model_accuracy: Mapped[float] = mapped_column(Float, nullable=True)  # Model accuracy score
    prediction_confidence: Mapped[float] = mapped_column(Float, nullable=True)  # Prediction confidence level
    false_positive_rate: Mapped[float] = mapped_column(Float, nullable=True)
    false_negative_rate: Mapped[float] = mapped_column(Float, nullable=True)

    # Predictive insights
    risk_predictions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON predicted risks
    compliance_trends: Mapped[str] = mapped_column(Text, nullable=True)  # JSON compliance trend predictions
    recommended_actions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON recommended preventive actions

    # Data processing
    data_preprocessing: Mapped[str] = mapped_column(Text, nullable=True)  # JSON preprocessing steps
    feature_engineering: Mapped[str] = mapped_column(Text, nullable=True)  # JSON feature engineering details
    model_features: Mapped[str] = mapped_column(Text, nullable=True)  # JSON model input features

    # Model artifacts
    model_parameters: Mapped[str] = mapped_column(Text, nullable=True)  # JSON model parameters
    training_data_summary: Mapped[str] = mapped_column(Text, nullable=True)  # JSON training data statistics
    validation_results: Mapped[str] = mapped_column(Text, nullable=True)  # JSON model validation results

    # Real-time capabilities
    real_time_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    update_frequency: Mapped[str] = mapped_column(String(50), nullable=True)  # hourly, daily, weekly, monthly
    last_model_update: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Alerts and notifications
    alert_thresholds: Mapped[str] = mapped_column(Text, nullable=True)  # JSON alert trigger thresholds
    notification_rules: Mapped[str] = mapped_column(Text, nullable=True)  # JSON notification configurations

    # Performance monitoring
    model_drift_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    performance_metrics: Mapped[str] = mapped_column(Text, nullable=True)  # JSON ongoing performance metrics

    # Governance
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    approved_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    approver = relationship("User", foreign_keys=[approved_by])


class AutomatedReporting(Base):
    """Automated reporting system for compliance analytics."""

    __tablename__ = "automated_reporting"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_name: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[str] = mapped_column(String(50), nullable=False)  # compliance_status, risk_dashboard, audit_findings, predictive_alerts

    # Report configuration
    report_template: Mapped[str] = mapped_column(Text, nullable=True)  # JSON report template structure
    data_sources: Mapped[str] = mapped_column(Text, nullable=True)  # JSON data sources for the report
    report_filters: Mapped[str] = mapped_column(Text, nullable=True)  # JSON filtering criteria

    # Scheduling and automation
    schedule_frequency: Mapped[str] = mapped_column(String(50), nullable=True)  # daily, weekly, monthly, quarterly, on_demand
    schedule_time: Mapped[str] = mapped_column(String(10), nullable=True)  # HH:MM format
    next_run_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    last_run_date: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Recipients and distribution
    recipients: Mapped[str] = mapped_column(Text, nullable=True)  # JSON list of recipients
    distribution_channels: Mapped[str] = mapped_column(Text, nullable=True)  # JSON email, dashboard, api, file_export
    access_permissions: Mapped[str] = mapped_column(Text, nullable=True)  # JSON access control rules

    # Report content
    executive_summary: Mapped[bool] = mapped_column(Boolean, default=True)
    detailed_findings: Mapped[bool] = mapped_column(Boolean, default=True)
    charts_and_graphs: Mapped[bool] = mapped_column(Boolean, default=True)
    recommendations: Mapped[bool] = mapped_column(Boolean, default=True)

    # Customization
    custom_sections: Mapped[str] = mapped_column(Text, nullable=True)  # JSON custom report sections
    branding_options: Mapped[str] = mapped_column(Text, nullable=True)  # JSON branding and styling
    language_settings: Mapped[str] = mapped_column(String(10), default="en")  # Language code

    # Automation features
    auto_generate_insights: Mapped[bool] = mapped_column(Boolean, default=True)
    predictive_elements: Mapped[bool] = mapped_column(Boolean, default=False)
    benchmark_comparisons: Mapped[bool] = mapped_column(Boolean, default=True)

    # Quality assurance
    review_required: Mapped[bool] = mapped_column(Boolean, default=False)
    reviewer_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    approval_workflow: Mapped[str] = mapped_column(Text, nullable=True)  # JSON approval process

    # Performance and monitoring
    generation_time_avg: Mapped[int] = mapped_column(Integer, nullable=True)  # Average generation time in seconds
    success_rate: Mapped[float] = mapped_column(Float, default=1.0)  # Success rate of report generation
    error_count: Mapped[int] = mapped_column(Integer, default=0)

    # Status
    status: Mapped[str] = mapped_column(String(50), default="active")  # active, paused, error, archived

    # Governance
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    last_modified_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    modifier = relationship("User", foreign_keys=[last_modified_by])
    reviewer = relationship("User", foreign_keys=[reviewer_id])
