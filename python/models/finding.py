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
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    finding_type: Mapped[FindingType] = mapped_column(SQLEnum(FindingType))
    finding_data: Mapped[dict] = mapped_column(JSON, nullable=False)  # Structured data
    severity: Mapped[Severity] = mapped_column(SQLEnum(Severity), default=Severity.INFO)
    is_new: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    dedup_hash: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    
    def __repr__(self) -> str:
        return f"<Finding(id={self.id}, type={self.finding_type}, severity={self.severity})>"