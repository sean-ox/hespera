"""Scope validation service."""
import fnmatch
from typing import List, Set, Optional
from pathlib import Path

from python.utils.logging_config import get_logger

logger = get_logger(__name__)


class ScopeValidator:
    """Validates if a subdomain is in scope based on patterns."""
    
    def __init__(self, scope_file_path: str):
        self.scope_file_path = Path(scope_file_path)
        self._patterns: List[str] = []
        self._load_patterns()
    
    def _load_patterns(self) -> None:
        """Load scope patterns from file."""
        if not self.scope_file_path.exists():
            logger.warning("Scope file not found", path=str(self.scope_file_path))
            return
        
        with open(self.scope_file_path) as f:
            self._patterns = [
                line.strip().lower()
                for line in f
                if line.strip() and not line.startswith('#')
            ]
        
        logger.info("Loaded scope patterns", count=len(self._patterns))
    
    def is_in_scope(self, subdomain: str) -> bool:
        """Check if a subdomain matches any scope pattern."""
        subdomain = subdomain.lower()
        
        for pattern in self._patterns:
            if pattern.startswith('*.'):
                # Wildcard pattern like *.example.com
                base = pattern[2:]  # Remove '*.
                if subdomain.endswith('.' + base) or subdomain == base:
                    return True
            elif pattern == subdomain:
                return True
            elif pattern.endswith('*'):
                # Prefix wildcard like api.*
                prefix = pattern[:-1]
                if subdomain.startswith(prefix):
                    return True
        
        return False
    
    def filter_scope(self, subdomains: List[str]) -> List[str]:
        """Filter list of subdomains to only in-scope items."""
        return [s for s in subdomains if self.is_in_scope(s)]