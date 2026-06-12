"""Notification worker - sends Telegram alerts."""
from python.workers.base import BaseWorker
from python.telegram.bot import send_message
from python.settings import load_settings
from python.utils.logging_config import get_logger

settings = load_settings()
logger = get_logger(__name__)


class NotifyWorker(BaseWorker):
    """Worker that sends notifications to Telegram."""
    
    def __init__(self):
        super().__init__("queue:notify", "notify_worker")
    
    async def process_job(self, job_data: dict) -> None:
        """Send notification based on job type."""
        msg_type = job_data.get("type")
        
        if msg_type == "recon_complete":
            text = (
                f"✅ <b>Recon Complete</b>\n"
                f"Domain: {job_data.get('domain')}\n"
                f"Subdomains: {job_data.get('subdomain_count', 0)}\n"
                f"URLs: {job_data.get('url_count', 0)}"
            )
            await send_message(settings.admin_chat_id, text)
        
        elif msg_type == "recon_failed":
            text = (
                f"❌ <b>Recon Failed</b>\n"
                f"Domain: {job_data.get('domain')}\n"
                f"Error: {job_data.get('error', 'Unknown')}"
            )
            await send_message(settings.admin_chat_id, text)
        
        elif msg_type == "vulnerabilities_found":
            vulns = job_data.get("vulnerabilities", [])
            if not vulns:
                return
            
            lines = [f"🔥 <b>Vulnerabilities Found!</b>\nDomain: {job_data.get('domain')}"]
            for v in vulns[:5]:
                severity_icon = {
                    "critical": "💀",
                    "high": "⚠️"
                }.get(v.get("severity"), "🔍")
                lines.append(f"{severity_icon} {v.get('template')}: {v.get('url')[:80]}")
            
            if len(vulns) > 5:
                lines.append(f"... and {len(vulns)-5} more")
            
            await send_message(settings.admin_chat_id, "\n".join(lines))
        
        else:
            logger.warning("Unknown notification type", type=msg_type)


async def main():
    worker = NotifyWorker()
    await worker.run()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
    