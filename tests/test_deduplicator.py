"""Tests for deduplication service."""
import pytest
from python.services.deduplicator import Deduplicator


class MockRedis:
    def __init__(self):
        self.data = {}
    
    async def cache_get(self, key):
        return self.data.get(key)
    
    async def cache_set(self, key, value, ttl=3600):
        self.data[key] = value


@pytest.fixture
def deduplicator():
    mock_redis = MockRedis()
    return Deduplicator(mock_redis)


class TestDeduplicator:
    def test_compute_hash_subdomain(self):
        dedup = Deduplicator(None)
        hash1 = dedup.compute_hash("subdomain", {"subdomain": "test.example.com"})
        hash2 = dedup.compute_hash("subdomain", {"subdomain": "test.example.com"})
        assert hash1 == hash2
    
    def test_compute_hash_url(self):
        dedup = Deduplicator(None)
        hash1 = dedup.compute_hash("url", {"url": "https://example.com/page?id=1"})
        hash2 = dedup.compute_hash("url", {"url": "https://example.com/page?id=1"})
        assert hash1 == hash2
    
    async def test_is_duplicate(self, deduplicator):
        data = {"subdomain": "test.example.com"}
        assert await deduplicator.is_duplicate("subdomain", data) is False
        assert await deduplicator.is_duplicate("subdomain", data) is True