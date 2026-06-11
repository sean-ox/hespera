"""Application settings with Pydantic validation."""
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, ValidationError
import re


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Telegram
    telegram_bot_token: str
    admin_chat_id: int
    
    # Database
    database_url: str = "postgresql+asyncpg://bugbounty:changeme@postgres:5432/bugbounty"
    
    # Redis
    redis_url: str = "redis://redis:6379/0"
    
    # Recon
    max_concurrent_recon: int = 2
    recon_timeout_seconds: int = 1800
    schedule_interval_minutes: int = 360
    scope_file: str = "/app/scope.txt"
    
    # Tool binaries
    subfinder_bin: str = "subfinder"
    assetfinder_bin: str = "assetfinder"
    httpx_bin: str = "httpx"
    gau_bin: str = "gau"
    waybackurls_bin: str = "waybackurls"
    katana_bin: str = "katana"
    nuclei_bin: str = "nuclei"
    
    # Logging
    log_level: str = "INFO"
    json_logs: bool = True
    
    # Health
    health_check_interval: int = 60
    
    @field_validator("telegram_bot_token")
    @classmethod
    def validate_bot_token(cls, v: str) -> str:
        """Validate Telegram bot token format."""
        if not re.match(r'^\d+:[A-Za-z0-9_-]{35}$', v):
            raise ValidationError("Invalid Telegram bot token format")
        return v
    
    @field_validator("admin_chat_id")
    @classmethod
    def validate_chat_id(cls, v: int) -> int:
        if v <= 0:
            raise ValidationError("Admin chat ID must be positive")
        return v
    
    @field_validator("max_concurrent_recon")
    @classmethod
    def validate_concurrent(cls, v: int) -> int:
        if v < 1 or v > 10:
            raise ValidationError("max_concurrent_recon must be between 1 and 10")
        return v


def load_settings() -> Settings:
    """Load and validate settings."""
    try:
        return Settings()  # type: ignore
    except ValidationError as e:
        raise SystemExit(f"Configuration error: {e}")