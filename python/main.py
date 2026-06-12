"""Main entry point for the orchestrator."""
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from python.database import db_manager
from python.redis_client import redis_client
from python.telegram.bot import create_bot_app
from python.scheduler import ReconScheduler
from python.utils.logging_config import setup_logging, get_logger

# Setup logging first
setup_logging()
logger = get_logger(__name__)


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


app = FastAPI(title="Bug Bounty Orchestrator", lifespan=lifespan)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "2.0.0"}


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    from prometheus_client import REGISTRY
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.get("/queue/length")
async def queue_length():
    """Get queue lengths for monitoring."""
    recon_len = await redis_client.get_queue_length("queue:recon")
    nuclei_len = await redis_client.get_queue_length("queue:nuclei")
    notify_len = await redis_client.get_queue_length("queue:notify")
    return {
        "recon_queue": recon_len,
        "nuclei_queue": nuclei_len,
        "notify_queue": notify_len
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)