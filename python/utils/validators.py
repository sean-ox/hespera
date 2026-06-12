"""Input validation utilities."""
import re
from typing import Optional

DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
SUBDOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')


def is_valid_domain(domain: str) -> bool:
    """Validate domain name format."""
    if not domain or len(domain) > 253:
        return False
    return bool(DOMAIN_REGEX.match(domain))


def is_valid_subdomain(subdomain: str) -> bool:
    """Validate subdomain format (more permissive than domain)."""
    if not subdomain or len(subdomain) > 253:
        return False
    return bool(SUBDOMAIN_REGEX.match(subdomain))


def sanitize_domain(domain: str) -> str:
    """Sanitize domain input - remove dangerous characters."""
    # Remove any non-domain characters
    cleaned = re.sub(r'[^a-zA-Z0-9.-]', '', domain)
    # Remove leading/trailing dots
    cleaned = cleaned.strip('.')
    return cleaned.lower()


def validate_chat_id(chat_id: int, admin_chat_id: int) -> bool:
    """Check if chat ID is authorized."""
    return chat_id == admin_chat_id


def is_safe_path(base_path: str, target_path: str) -> bool:
    """Check if target path is within base path (防止路径遍历)."""
    import os
    real_base = os.path.realpath(base_path)
    real_target = os.path.realpath(os.path.join(real_base, target_path))
    return real_target.startswith(real_base)