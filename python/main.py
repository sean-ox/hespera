"""Main entry point for the orchestrator."""
import asyncio
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

from python.database import db_manager
from python.redis_client import redis_client
from python.telegram.bot import create_bot_app
from python.scheduler import ReconScheduler
from python.utils.logging_config import setup_logging, get_logger

# Setup logging first
setup_logging()
logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# API Key authentication
# ---------------------------------------------------------------------------
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_API_SECRET_KEY: str = os.environ.get("API_SECRET_KEY", "")


def _verify_api_key(api_key: str = Security(_API_KEY_HEADER)) -> str:
    """
    Dependency that validates the X-API-Key header.

    The key is compared with secrets.compare_digest() to prevent
    timing-based side-channel attacks.
    Raises HTTP 403 if the key is missing or incorrect.
    """
    if not _API_SECRET_KEY:
        # Fail-closed: if the operator never set API_SECRET_KEY, block all
        # access rather than allow unauthenticated requests.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API authentication is not configured on this server.",
        )
    if not api_key or not secrets.compare_digest(api_key, _API_SECRET_KEY):
        logger.warning("Rejected request with invalid API key")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key.",
        )
    return api_key


# ---------------------------------------------------------------------------
# Application lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting Bug Bounty Platform v2.0")

    # Initialize connections
    await db_manager.initialize()
    await redis_client.initialize()

    # Start Telegram bot
    bot_app = create_bot_app()
    await bot_app.initialize()
    await bot_app.start()
    await bot_app.updater.start_polling()
    logger.info("Telegram bot started")

    # Start scheduler
    scheduler = ReconScheduler()
    await scheduler.start()

    yield

    # Cleanup
    await scheduler.stop()
    await bot_app.updater.stop()
    await bot_app.stop()
    await bot_app.shutdown()
    await db_manager.close()
    await redis_client.close()
    logger.info("Shutdown complete")


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Bug Bounty Orchestrator",
    lifespan=lifespan,
    # Hide schema endpoints in production
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


# Public — used by Docker / load-balancer health probes (no auth required)
@app.get("/health")
async def health_check():
    """Liveness probe. No authentication required."""
    return {"status": "healthy", "version": "2.0.0"}


# Protected — requires X-API-Key header
@app.get("/metrics", dependencies=[Depends(_verify_api_key)])
async def metrics():
    """Prometheus metrics endpoint. Requires X-API-Key."""
    from prometheus_client import REGISTRY
    return Response(
        content=generate_latest(REGISTRY),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.get("/queue/length", dependencies=[Depends(_verify_api_key)])
async def queue_length():
    """Get queue lengths for monitoring. Requires X-API-Key."""
    recon_len = await redis_client.get_queue_length("queue:recon")
    nuclei_len = await redis_client.get_queue_length("queue:nuclei")
    notify_len = await redis_client.get_queue_length("queue:notify")
    return {
        "recon_queue": recon_len,
        "nuclei_queue": nuclei_len,
        "notify_queue": notify_len,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)