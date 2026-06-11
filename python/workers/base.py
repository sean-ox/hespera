"""Base worker class for all background workers."""
import asyncio
import signal
from abc import ABC, abstractmethod
from typing import Optional

from python.database import db_manager
from python.redis_client import redis_client
from python.utils.logging_config import get_logger
from python.settings import load_settings

settings = load_settings()
logger = get_logger(__name__)


class BaseWorker(ABC):
    """Abstract base class for all workers."""
    
    def __init__(self, queue_name: str, worker_name: str):
        self.queue_name = queue_name
        self.worker_name = worker_name
        self._running = True
        self._poll_interval = 1
    
    @abstractmethod
    async def process_job(self, job_data: dict) -> None:
        """Process a single job. Must be implemented by subclass."""
        pass
    
    async def run(self) -> None:
        """Main worker loop."""
        logger.info("Starting worker", worker=self.worker_name, queue=self.queue_name)
        
        # Setup signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.shutdown()))
        
        # Initialize connections
        await db_manager.initialize()
        await redis_client.initialize()
        
        try:
            while self._running:
                job = await redis_client.dequeue(self.queue_name, timeout=self._poll_interval)
                if job:
                    logger.info("Processing job", worker=self.worker_name, job_id=job.get('job_id'))
                    try:
                        await self.process_job(job.get('data', {}))
                        logger.info("Job completed", worker=self.worker_name, job_id=job.get('job_id'))
                    except Exception as e:
                        logger.exception(
                            "Job failed",
                            worker=self.worker_name,
                            job_id=job.get('job_id'),
                            error=str(e)
                        )
                await asyncio.sleep(0.1)
        finally:
            await self.cleanup()
    
    async def shutdown(self) -> None:
        """Gracefully shut down the worker."""
        logger.info("Shutting down worker", worker=self.worker_name)
        self._running = False
    
    async def cleanup(self) -> None:
        """Cleanup resources."""
        await db_manager.close()
        await redis_client.close()
        logger.info("Worker stopped", worker=self.worker_name)