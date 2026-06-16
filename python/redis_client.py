"""Redis client for queue and cache."""
import json
from typing import Optional, Any

import redis.asyncio as redis
from redis.asyncio import Redis

from python.settings import load_settings

settings = load_settings()


class RedisClient:
    """Async Redis client wrapper."""
    
    def __init__(self, redis_url: str):
        self._redis_url = redis_url
        self._client: Optional[Redis] = None
    
    async def initialize(self) -> None:
        """Initialize Redis connection."""
        self._client = await redis.from_url(
            self._redis_url,
            decode_responses=True,
            max_connections=20,
        )
    
    async def close(self) -> None:
        """Close Redis connection."""
        if self._client:
            await self._client.close()
    
    async def enqueue(self, queue_name: str, data: dict, delay: int = 0) -> str:
        """Enqueue a job."""
        job_id = f"{queue_name}:{data.get('id', 'unknown')}"
        payload = json.dumps({
            "job_id": job_id,
            "data": data,
            "created_at": None,  # will be set by worker
        })
        if delay > 0:
            await self._client.zadd(f"delayed:{queue_name}", {payload: delay})
        else:
            await self._client.lpush(queue_name, payload)
        return job_id
    
    async def dequeue(self, queue_name: str, timeout: int = 5) -> Optional[dict]:
        """Dequeue a job with timeout."""
        result = await self._client.brpop(queue_name, timeout=timeout)
        if result:
            _, payload = result
            return json.loads(payload)
        return None
    
    async def get_queue_length(self, queue_name: str) -> int:
        """Get number of pending jobs."""
        return await self._client.llen(queue_name)
    
    async def cache_get(self, key: str) -> Optional[str]:
        """Get value from cache."""
        return await self._client.get(key)
    
    async def cache_set(self, key: str, value: str, ttl: int = 3600) -> None:
        """Set value in cache with TTL."""
        await self._client.setex(key, ttl, value)
    
    async def acquire_lock(self, lock_name: str, timeout: int = 30) -> bool:
        """Acquire a distributed lock atomically.

        Uses SET NX EX — a single atomic Redis command — so there is no
        window between SETNX and EXPIRE where a crash would leave an
        un-expiring lock that deadlocks all future callers.

        Returns True if the lock was acquired, False if it was already held.
        """
        result = await self._client.set(
            f"lock:{lock_name}",
            "locked",
            ex=timeout,   # expire in `timeout` seconds
            nx=True,      # only set if key does NOT already exist
        )
        # redis-py returns the string "OK" (or True) on success, None on failure
        return result is not None

    async def release_lock(self, lock_name: str) -> None:
        """Release the distributed lock."""
        await self._client.delete(f"lock:{lock_name}")


# Global instance
redis_client = RedisClient(settings.redis_url)


async def get_redis() -> RedisClient:
    """Dependency for FastAPI."""
    return redis_client