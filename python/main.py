"""Main entry point for the orchestrator."""
import asyncio
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Security, status, Request
from fastapi.security.api_key import APIKeyHeader
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

from python.database import db_manager
from python.redis_client import redis_client
from python.telegram.bot import create_bot_app
from python.telegram.bot import send_message
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
    if not _API_SECRET_KEY:
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
    logger.info("Starting Bug Bounty Platform v2.0")

    await db_manager.initialize()
    await db_manager.create_tables()
    await redis_client.initialize()

    # Start Telegram bot (polling)
    bot_app = create_bot_app()
    await bot_app.initialize()
    await bot_app.start()
    await bot_app.updater.start_polling()
    logger.info("Telegram bot started (polling mode)")

    scheduler = ReconScheduler()
    await scheduler.start()

    yield

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
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "2.0.0"}


@app.get("/metrics", dependencies=[Depends(_verify_api_key)])
async def metrics():
    from prometheus_client import REGISTRY
    return Response(
        content=generate_latest(REGISTRY),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.get("/queue/length", dependencies=[Depends(_verify_api_key)])
async def queue_length():
    recon_len = await redis_client.get_queue_length("queue:recon")
    nuclei_len = await redis_client.get_queue_length("queue:nuclei")
    notify_len = await redis_client.get_queue_length("queue:notify")
    return {
        "recon_queue": recon_len,
        "nuclei_queue": nuclei_len,
        "notify_queue": notify_len,
    }


# ===================== WEBHOOK ENDPOINT (OPSIONAL) =====================
@app.post("/webhook")
async def telegram_webhook(request: Request):
    """
    Endpoint untuk menerima update dari Telegram (webhook).
    Jika kamu ingin menggunakan webhook, setel URL webhook di Telegram.
    """
    data = await request.json()
    
    # Abaikan jika bukan pesan
    if "message" not in data:
        return {"ok": True}
    
    msg = data["message"]
    chat_id = msg["chat"]["id"]
    text = msg.get("text", "").strip()
    
    # Proses perintah menggunakan handler yang sama
    from python.telegram.handlers import process_telegram_command
    response = process_telegram_command(chat_id, text)
    if response:
        await send_message(chat_id, response)
    
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
