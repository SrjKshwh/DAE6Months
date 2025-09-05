# models.py
from datetime import datetime, timezone
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Boolean, DateTime, ForeignKey, Text, Float, Enum
from enum import Enum as PyEnum

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

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    uploads: Mapped[list["Upload"]] = relationship("Upload", back_populates="user")

class Upload(Base):
    __tablename__ = "uploads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    saved_path: Mapped[str] = mapped_column(String(512), nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc))

    user: Mapped["User"] = relationship("User", back_populates="uploads")
    scan_result: Mapped["ScanResult"] = relationship("ScanResult", back_populates="upload", uselist=False)

class ScanResult(Base):
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
    severity: Mapped[RiskSeverity] = mapped_column(Enum(RiskSeverity), default=RiskSeverity.MEDIUM)

    ale: Mapped[float] = mapped_column(Float, default=0.0)         # Annualized Loss Expectancy
    emv: Mapped[float] = mapped_column(Float, default=0.0)         # Expected Monetary Value

    mitigation_plan: Mapped[str] = mapped_column(Text, nullable=True)
    residual_risk: Mapped[str] = mapped_column(Text, nullable=True)
    owner: Mapped[str] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    compliance = relationship("Compliance", back_populates="risk")
    scan_result_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_results.id"), nullable=True)
    scan_result = relationship("ScanResult", back_populates="risks")

    def calculate_score(self):
        """Calculate risk score using likelihood × impact"""
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

    def calculate_ale(self, asset_value: float = 100000.0):
        """Calculate Annualized Loss Expectancy"""
        self.ale = (self.likelihood / 5.0) * (self.impact / 5.0) * asset_value

    def calculate_emv(self, mitigation_cost: float = 0.0):
        """Calculate Expected Monetary Value"""
        self.emv = self.ale - mitigation_cost


class Compliance(Base):
    __tablename__ = "compliance_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[ComplianceFramework] = mapped_column(Enum(ComplianceFramework), nullable=False)
    control: Mapped[str] = mapped_column(String(255), nullable=False)
    control_family: Mapped[str] = mapped_column(String(100), nullable=True)  # e.g., AC, IR, AU
    score: Mapped[float] = mapped_column(Float, default=0.0)           # percentage compliance 0-100
    status: Mapped[str] = mapped_column(String(50), default="not_assessed")  # compliant, non-compliant, not_assessed

    risk_id: Mapped[int] = mapped_column(Integer, ForeignKey("risks.id"), nullable=True)
    risk = relationship("Risk", back_populates="compliance")

    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class Dependency(Base):
    __tablename__ = "dependencies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    version: Mapped[str] = mapped_column(String, nullable=False)
    risk: Mapped[str] = mapped_column(String)         # e.g., CVE found / None
    mitigation: Mapped[str] = mapped_column(String)   # recommended fix
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))