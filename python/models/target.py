"""Target model - domains to scan."""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Boolean, Enum as SQLEnum
from sqlalchemy.orm import Mapped, mapped_column
import enum

from python.database import Base


class ScanMode(str, enum.Enum):
    SAFE = "safe"
    AGGRESSIVE = "aggressive"


class TargetStatus(str, enum.Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    REMOVED = "removed"


class Target(Base):
    __tablename__ = "targets"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    scope_pattern: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[TargetStatus] = mapped_column(
        SQLEnum(TargetStatus), default=TargetStatus.ACTIVE
    )
    scan_mode: Mapped[ScanMode] = mapped_column(
        SQLEnum(ScanMode), default=ScanMode.SAFE
    )
    created_by_chat_id: Mapped[Optional[int]] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    last_recon_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    
    def __repr__(self) -> str:
        return f"<Target(domain={self.domain}, mode={self.scan_mode})>"