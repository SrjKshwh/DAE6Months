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