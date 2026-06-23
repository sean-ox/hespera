"""Finding model - stores discovered vulnerabilities and assets."""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Integer, Text, ForeignKey, Boolean, JSON, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column
import enum

from python.database import Base


class FindingType(str, enum.Enum):
    SUBDOMAIN = "subdomain"
    URL = "url"
    VULNERABILITY = "vulnerability"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(Base):
    __tablename__ = "findings"

    # ====== Field yang diisi otomatis ======
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True, init=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default_factory=datetime.utcnow, index=True, init=False
    )

    # ====== Field wajib ======
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), index=True
    )
    finding_type: Mapped[FindingType] = mapped_column(
        SQLEnum(FindingType, native_enum=False)
    )
    finding_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    dedup_hash: Mapped[str] = mapped_column(String(64), index=True)

    # ====== Field dengan default ======
    severity: Mapped[Severity] = mapped_column(
        SQLEnum(Severity, native_enum=False), default=Severity.INFO
    )
    is_new: Mapped[bool] = mapped_column(Boolean, default=True, index=True)

    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, type={self.finding_type}, severity={self.severity})>"
