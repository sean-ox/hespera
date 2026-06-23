"""Target model - domains to scan."""
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Enum as SQLEnum, BigInteger  # ← import BigInteger
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

    # ====== Field yang diisi otomatis (tidak perlu di-init) ======
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True, init=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default_factory=datetime.utcnow, init=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default_factory=datetime.utcnow,
        onupdate=datetime.utcnow,
        init=False
    )

    # ====== Field wajib ======
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    # ====== Field opsional ======
    scope_pattern: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, default=None
    )
    # 🔥 PERBAIKAN: gunakan BigInteger agar muat chat_id besar
    created_by_chat_id: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True, default=None
    )
    last_recon_at: Mapped[Optional[datetime]] = mapped_column(
        nullable=True, default=None
    )

    # ====== Field dengan default ======
    status: Mapped[TargetStatus] = mapped_column(
        SQLEnum(TargetStatus, native_enum=False), default=TargetStatus.ACTIVE
    )
    scan_mode: Mapped[ScanMode] = mapped_column(
        SQLEnum(ScanMode, native_enum=False), default=ScanMode.SAFE
    )

    def __repr__(self) -> str:
        return f"<Target(domain={self.domain}, mode={self.scan_mode})>"
