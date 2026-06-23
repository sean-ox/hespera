"""Scheduler for periodic recon tasks."""
import asyncio
from datetime import datetime
from urllib.parse import urlparse

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


def _build_redis_jobstore() -> RedisJobStore:
    """
    Build a RedisJobStore from settings.redis_url.

    Parses the URL (redis://:password@host:port/db) so that the
    jobstore always uses the same credentials and host as the rest
    of the application — no more hardcoded host/port/no-password.

    APScheduler stores scheduled job metadata in Redis db=1
    (separate from application queues on db=0).
    """
    parsed = urlparse(settings.redis_url)

    host     = parsed.hostname or "redis"
    port     = parsed.port     or 6379
    password = parsed.password or None   # None if not in URL

    logger.info(
        "Configuring APScheduler Redis jobstore",
        host=host,
        port=port,
        auth=bool(password),
    )

    return RedisJobStore(
        host=host,
        port=port,
        password=password,          # ← was always None before this fix
        db=1,                       # keep scheduler data on db=1
        jobs_key="apscheduler.jobs",
        run_times_key="apscheduler.run_times",
    )


# ===================== FUNGSI JOB TINGKAT MODUL =====================
async def _scheduled_recon_job() -> None:
    """
    Job yang dijadwalkan untuk menjalankan recon pada semua target aktif.
    Didefinisikan di tingkat modul agar tidak mereferensi scheduler,
    sehingga bisa diserialisasi oleh RedisJobStore.
    """
    from python.database import db_manager
    from python.models.target import Target, TargetStatus
    from python.workers.recon_worker import enqueue_recon
    from python.utils.logging_config import get_logger
    from python.settings import load_settings

    logger = get_logger(__name__)
    settings = load_settings()

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
            triggered_by=None,  # Scheduled, not user-triggered
        )


# ===================== SCHEDULER KELAS =====================
class ReconScheduler:
    """Schedules periodic recon for all active targets."""

    def __init__(self):
        self.scheduler = None
        self._running = False

    async def start(self) -> None:
        """Start the APScheduler with a Redis-backed jobstore."""
        await db_manager.initialize()
        await redis_client.initialize()

        jobstores = {"default": _build_redis_jobstore()}

        self.scheduler = AsyncIOScheduler(jobstores=jobstores)

        # 🔥 Perbaikan: gunakan fungsi tingkat modul, bukan metode instance
        self.scheduler.add_job(
            _scheduled_recon_job,                 # ← fungsi statis/modul
            IntervalTrigger(minutes=settings.schedule_interval_minutes),
            id="global_recon_schedule",
            replace_existing=True,
        )

        self.scheduler.start()
        self._running = True
        logger.info(
            "Scheduler started",
            interval_minutes=settings.schedule_interval_minutes,
        )

    async def stop(self) -> None:
        """Stop the scheduler gracefully."""
        if self.scheduler:
            self.scheduler.shutdown(wait=True)
            self._running = False
        await db_manager.close()
        await redis_client.close()
        logger.info("Scheduler stopped")


# ===================== MAIN (UNTUK TESTING) =====================
async def main():
    scheduler = ReconScheduler()
    try:
        await scheduler.start()
        while True:
            await asyncio.sleep(10)
    except KeyboardInterrupt:
        await scheduler.stop()


if __name__ == "__main__":
    asyncio.run(main())
