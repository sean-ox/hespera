"""Scheduler for periodic recon tasks."""
import asyncio
from datetime import datetime

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.redis import RedisJobStore

from python.database import db_manager
from python.redis_client import redis_client
from python.models.target import Target, TargetStatus
from python.workers.recon_worker import enqueue_recon
from python.utils.logging_config import get_logger
from python.settings import load_settings

settings = load_settings()
logger = get_logger(__name__)


class ReconScheduler:
    """Schedules periodic recon for all active targets."""
    
    def __init__(self):
        self.scheduler = None
        self._running = False
    
    async def start(self):
        """Start the scheduler."""
        await db_manager.initialize()
        await redis_client.initialize()
        
        # Use Redis for job persistence
        jobstores = {
            'default': RedisJobStore(
                host='redis',
                port=6379,
                db=1,
                jobs_key='apscheduler.jobs',
                run_times_key='apscheduler.run_times'
            )
        }
        
        self.scheduler = AsyncIOScheduler(jobstores=jobstores)
        
        # Schedule periodic recon for all targets
        self.scheduler.add_job(
            self._run_scheduled_recon,
            IntervalTrigger(minutes=settings.schedule_interval_minutes),
            id="global_recon_schedule",
            replace_existing=True
        )
        
        self.scheduler.start()
        self._running = True
        logger.info("Scheduler started", interval_minutes=settings.schedule_interval_minutes)
    
    async def _run_scheduled_recon(self):
        """Fetch all active targets and enqueue recon jobs."""
        async with db_manager.session() as session:
            from sqlalchemy import select
            stmt = select(Target).where(Target.status == TargetStatus.ACTIVE)
            result = await session.execute(stmt)
            targets = result.scalars().all()
        
        logger.info("Running scheduled recon", target_count=len(targets))
        
        for target in targets:
            await enqueue_recon(
                target.domain,
                target.scan_mode.value,
                triggered_by=None  # Scheduled, not user-triggered
            )
    
    async def stop(self):
        """Stop the scheduler gracefully."""
        if self.scheduler:
            self.scheduler.shutdown(wait=True)
            self._running = False
        await db_manager.close()
        await redis_client.close()
        logger.info("Scheduler stopped")


async def main():
    scheduler = ReconScheduler()
    try:
        await scheduler.start()
        # Keep running
        while True:
            await asyncio.sleep(10)
    except KeyboardInterrupt:
        await scheduler.stop()


if __name__ == "__main__":
    asyncio.run(main())