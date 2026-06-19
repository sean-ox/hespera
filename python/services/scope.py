"""Scope validation service."""
import sys
from typing import List
from pathlib import Path

from python.utils.logging_config import get_logger

logger = get_logger(__name__)


def _validate_pattern(pattern: str) -> None:
    """
    Raise ValueError for patterns that would match too broadly.

    Allowed forms:
        *.example.com     — all subdomains of example.com
        example.com       — exact match
        api.example.com   — exact subdomain match

    Rejected forms:
        *                 — matches everything
        api.*             — prefix wildcard matches external domains
        *.                — degenerate
    """
    if pattern == "*":
        raise ValueError(
            f"Scope pattern '*' is not allowed — it matches every hostname. "
            f"Use '*.example.com' for wildcard subdomains."
        )
    if pattern.endswith("*") and not pattern.startswith("*."):
        raise ValueError(
            f"Prefix wildcard pattern '{pattern}' is not allowed. "
            f"It can match domains outside your programme scope. "
            f"Use '*.example.com' instead."
        )
    if pattern == "*.":
        raise ValueError(f"Degenerate pattern '*.' is not allowed.")


class ScopeValidator:
    """Validates whether a subdomain is in scope based on patterns in scope.txt.

    Supported pattern syntax:
        *.example.com  — matches sub.example.com, a.b.example.com, example.com
        example.com    — exact match only

    Patterns are validated on load; the process will exit if any pattern is
    dangerously broad (e.g. bare '*' or prefix wildcards like 'api.*').
    """

    def __init__(self, scope_file_path: str):
        self.scope_file_path = Path(scope_file_path)
        self._patterns: List[str] = []
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load and validate scope patterns from file."""
        if not self.scope_file_path.exists():
            # Hard failure: operating without scope is dangerous
            logger.error(
                "Scope file not found — refusing to start without scope definition.",
                path=str(self.scope_file_path),
            )
            sys.exit(1)

        if not self.scope_file_path.is_file():
            logger.error(
                "Scope file path is a directory, not a file.",
                path=str(self.scope_file_path),
            )
            sys.exit(1)

        raw_patterns: List[str] = []
        with open(self.scope_file_path) as fh:
            for lineno, line in enumerate(fh, start=1):
                stripped = line.strip().lower()
                if not stripped or stripped.startswith("#"):
                    continue
                try:
                    _validate_pattern(stripped)
                except ValueError as exc:
                    logger.error(
                        "Invalid scope pattern",
                        file=str(self.scope_file_path),
                        line=lineno,
                        pattern=stripped,
                        reason=str(exc),
                    )
                    sys.exit(1)
                raw_patterns.append(stripped)

        if not raw_patterns:
            logger.error(
                "Scope file is empty — refusing to start without scope definition.",
                path=str(self.scope_file_path),
            )
            sys.exit(1)

        self._patterns = raw_patterns
        logger.info("Loaded scope patterns", count=len(self._patterns))

    def is_in_scope(self, subdomain: str) -> bool:
        """
        Return True if *subdomain* matches at least one scope pattern.

        Pattern matching rules:
        - '*.example.com' matches 'sub.example.com' and 'example.com' itself
          but NOT 'notexample.com' or 'evil-example.com'
        - 'example.com' matches only 'example.com' exactly
        """
        subdomain = subdomain.strip().lower()
        if not subdomain:
            return False

        for pattern in self._patterns:
            if pattern.startswith("*."):
                # Wildcard: *.example.com
                base = pattern[2:]   # → "example.com"
                if subdomain == base:
                    return True
                # Must end with '.' + base to prevent 'notexample.com' matching
                if subdomain.endswith("." + base):
                    return True
            else:
                # Exact match
                if subdomain == pattern:
                    return True

        return False

    def filter_scope(self, subdomains: List[str]) -> List[str]:
        """Return only the subdomains that are in scope."""
        return [s for s in subdomains if self.is_in_scope(s)]