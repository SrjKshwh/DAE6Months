# models.py
from datetime import datetime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Boolean, DateTime, ForeignKey, Text

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
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    user: Mapped["User"] = relationship("User", back_populates="uploads")
    scan_result: Mapped["ScanResult"] = relationship("ScanResult", back_populates="upload", uselist=False)

class ScanResult(Base):
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    upload_id: Mapped[int] = mapped_column(ForeignKey("uploads.id"), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=True)
    compliance_hits_json: Mapped[str] = mapped_column(Text, nullable=True)   # JSON as text
    risks_json: Mapped[str] = mapped_column(Text, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    upload: Mapped["Upload"] = relationship("Upload", back_populates="scan_result")



class Risk(Base):
    __tablename__ = "risks"

    id = Column(Integer, primary_key=True)
    asset = Column(String, nullable=False)
    threat = Column(String, nullable=False)
    vulnerability = Column(String, nullable=False)
    control = Column(String, nullable=False)
    compliance_standard = Column(String)  # NIST, ISO, PCI-DSS, HIPAA
    status = Column(String, default="open")

    likelihood = Column(Integer, default=1)  # 1–5
    impact = Column(Integer, default=1)      # 1–5
    score = Column(Integer, default=0)       # likelihood × impact
    ale = Column(Float, default=0.0)         # Annualized Loss Expectancy
    emv = Column(Float, default=0.0)         # Expected Monetary Value

    created_at = Column(DateTime, default=datetime.utcnow)

    compliance = relationship("Compliance", back_populates="risk")

    def calculate_score(self):
        self.score = self.likelihood * self.impact


class Compliance(Base):
    __tablename__ = "compliance_scores"

    id = Column(Integer, primary_key=True)
    framework = Column(String, nullable=False)   # NIST CSF, ISO27001
    control = Column(String, nullable=False)
    score = Column(Float, default=0.0)           # percentage compliance

    risk_id = Column(Integer, ForeignKey("risks.id"))
    risk = relationship("Risk", back_populates="compliance")


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    version = Column(String, nullable=False)
    risk = Column(String)         # e.g., CVE found / None
    mitigation = Column(String)   # recommended fix
    checked_at = Column(DateTime, default=datetime.utcnow)