"""Deduplication service to prevent duplicate findings."""
import hashlib
from typing import Dict, Any, Optional

from python.redis_client import redis_client
from python.utils.logging_config import get_logger

logger = get_logger(__name__)


class Deduplicator:
    """Handles deduplication of findings using Redis cache."""
    
    def __init__(self, redis_client_instance):
        self.redis = redis_client_instance
        self._cache_ttl = 86400 * 30  # 30 days
    
    @staticmethod
    def compute_hash(finding_type: str, data: Dict[str, Any]) -> str:
        """
        Compute a deterministic hash for a finding.
        
        Different finding types use different fields for deduplication.
        """
        if finding_type == "subdomain":
            key = data.get("subdomain", "")
        elif finding_type == "url":
            key = data.get("url", "")
        elif finding_type == "vulnerability":
            # Combine URL + template ID + severity
            key = f"{data.get('url','')}:{data.get('template_id','')}:{data.get('severity','')}"
        else:
            key = str(data)
        
        return hashlib.sha256(key.encode()).hexdigest()
    
    async def is_duplicate(self, finding_type: str, data: Dict[str, Any]) -> bool:
        """Check if a finding already exists."""
        hash_key = self.compute_hash(finding_type, data)
        cache_key = f"dedup:{finding_type}:{hash_key}"
        
        exists = await self.redis.cache_get(cache_key)
        if exists:
            logger.debug("Duplicate found", type=finding_type, hash=hash_key[:8])
            return True
        
        # Store with TTL
        await self.redis.cache_set(cache_key, "1", ttl=self._cache_ttl)
        return False
    
    async def mark_seen(self, finding_type: str, data: Dict[str, Any]) -> None:
        """Manually mark a finding as seen (for known false positives)."""
        hash_key = self.compute_hash(finding_type, data)
        cache_key = f"dedup:{finding_type}:{hash_key}"
        await self.redis.cache_set(cache_key, "1", ttl=self._cache_ttl)