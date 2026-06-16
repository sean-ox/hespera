"""Application settings with Pydantic validation."""
import re
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    All fields without a default value MUST be supplied via environment
    variables or a .env file. The application will refuse to start if any
    required field is missing or invalid.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Telegram  (required — no defaults)
    # ------------------------------------------------------------------
    telegram_bot_token: str
    admin_chat_id: int

    # ------------------------------------------------------------------
    # Database  (required — no insecure defaults)
    # ------------------------------------------------------------------
    database_url: str

    # ------------------------------------------------------------------
    # Redis  (required — no insecure defaults)
    # ------------------------------------------------------------------
    redis_url: str

    # ------------------------------------------------------------------
    # API authentication  (required)
    # ------------------------------------------------------------------
    api_secret_key: str

    # ------------------------------------------------------------------
    # Recon tunables  (safe defaults are acceptable here)
    # ------------------------------------------------------------------
    max_concurrent_recon: int = 2
    recon_timeout_seconds: int = 1800
    schedule_interval_minutes: int = 360
    scope_file: str = "/app/scope.txt"

    # ------------------------------------------------------------------
    # Tool binary names  (overridable via env, safe defaults)
    # ------------------------------------------------------------------
    subfinder_bin: str = "subfinder"
    assetfinder_bin: str = "assetfinder"
    httpx_bin: str = "httpx"
    gau_bin: str = "gau"
    waybackurls_bin: str = "waybackurls"
    katana_bin: str = "katana"
    nuclei_bin: str = "nuclei"
    uro_bin: str = "uro"
    unfurl_bin: str = "unfurl"
    qsreplace_bin: str = "qsreplace"
    dalfox_bin: str = "dalfox"
    subzy_bin: str = "subzy"
    jsluice_bin: str = "jsluice"
    trufflehog_bin: str = "trufflehog"

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------
    log_level: str = "INFO"
    json_logs: bool = True

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------
    health_check_interval: int = 60

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------
    @field_validator("telegram_bot_token")
    @classmethod
    def validate_bot_token(cls, v: str) -> str:
        """Validate Telegram bot token format (e.g. 123456789:AAFxxxx...)."""
        if not re.match(r"^\d+:[A-Za-z0-9_-]{35}$", v):
            # Raise ValueError — Pydantic converts this to ValidationError
            raise ValueError(
                "TELEGRAM_BOT_TOKEN has invalid format. "
                "Expected: <numeric_id>:<35_alphanumeric_chars>"
            )
        return v

    @field_validator("admin_chat_id")
    @classmethod
    def validate_chat_id(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("ADMIN_CHAT_ID must be a positive integer.")
        return v

    @field_validator("max_concurrent_recon")
    @classmethod
    def validate_concurrent(cls, v: int) -> int:
        if v < 1 or v > 10:
            raise ValueError("MAX_CONCURRENT_RECON must be between 1 and 10.")
        return v

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v.startswith("postgresql"):
            raise ValueError(
                "DATABASE_URL must be a PostgreSQL URL "
                "(e.g. postgresql+asyncpg://user:pass@host:5432/db)."
            )
        return v

    @field_validator("api_secret_key")
    @classmethod
    def validate_api_key(cls, v: str) -> str:
        if len(v) < 16:
            raise ValueError(
                "API_SECRET_KEY must be at least 16 characters. "
                "Generate one with: python3 -c \"import secrets; print(secrets.token_urlsafe(32))\""
            )
        return v


def load_settings() -> Settings:
    """Load and validate settings. Exits with a clear error if anything is missing."""
    from pydantic import ValidationError

    try:
        return Settings()  # type: ignore
    except ValidationError as exc:
        # Format pydantic v2 errors into human-readable lines
        lines = ["", "=== Configuration Error — cannot start ==="]
        for error in exc.errors():
            field = " → ".join(str(loc) for loc in error["loc"])
            lines.append(f"  {field}: {error['msg']}")
        lines.append("")
        raise SystemExit("\n".join(lines)) from exc