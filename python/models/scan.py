"""Scan model - tracks each recon execution."""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Integer, Text, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column
import enum

from python.database import Base


class ScanType(str, enum.Enum):
    FULL = "full"
    SUBDOMAIN_ONLY = "subdomain_only"
    URL_ONLY = "url_only"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class Scan(Base):
    __tablename__ = "scans"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    scan_type: Mapped[ScanType] = mapped_column(SQLEnum(ScanType), default=ScanType.FULL)
    status: Mapped[ScanStatus] = mapped_column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    started_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON string
    
    def __repr__(self) -> str:
        return f"<Scan(id={self.id}, target={self.target_id}, status={self.status})>"