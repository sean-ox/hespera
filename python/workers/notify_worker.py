"""Notification worker - sends Telegram alerts."""
import asyncio
import html as html_lib
from typing import Any

from python.workers.base import BaseWorker
from python.telegram.bot import send_message
from python.settings import load_settings
from python.utils.logging_config import get_logger

settings = load_settings()
logger = get_logger(__name__)


def _e(value: Any, max_len: int = 200) -> str:
    """
    Escape a value for safe embedding in a Telegram HTML message.

    - Converts value to str
    - Truncates to max_len characters
    - Escapes <, >, &, " so they cannot inject HTML tags
    """
    return html_lib.escape(str(value)[:max_len])


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
                f"Domain: {_e(job_data.get('domain', ''))}\n"
                f"Subdomains: {_e(job_data.get('subdomain_count', 0))}\n"
                f"URLs: {_e(job_data.get('url_count', 0))}"
            )
            await send_message(settings.admin_chat_id, text)

        elif msg_type == "recon_failed":
            text = (
                f"❌ <b>Recon Failed</b>\n"
                f"Domain: {_e(job_data.get('domain', ''))}\n"
                f"Error: {_e(job_data.get('error', 'Unknown'))}"
            )
            await send_message(settings.admin_chat_id, text)

        elif msg_type == "vulnerabilities_found":
            vulns = job_data.get("vulnerabilities", [])
            if not vulns:
                return

            lines = [
                f"🔥 <b>Vulnerabilities Found!</b>\n"
                f"Domain: {_e(job_data.get('domain', ''))}"
            ]
            for v in vulns[:5]:
                severity_icon = {
                    "critical": "💀",
                    "high": "⚠️",
                }.get(str(v.get("severity", "")).lower(), "🔍")
                template = _e(v.get("template", "unknown"), max_len=60)
                url = _e(v.get("url", ""), max_len=80)
                lines.append(f"{severity_icon} {template}: {url}")

            if len(vulns) > 5:
                lines.append(f"... and {len(vulns) - 5} more")

            await send_message(settings.admin_chat_id, "\n".join(lines))

        elif msg_type == "xss_found":
            findings = job_data.get("findings", [])
            if not findings:
                return
            lines = [
                f"⚡ <b>XSS Found!</b>\n"
                f"Domain: {_e(job_data.get('domain', ''))}"
            ]
            for f in findings[:5]:
                url = _e(f.get("url", ""), max_len=80)
                payload = _e(f.get("payload", ""), max_len=60)
                lines.append(f"🎯 {url}\n   Payload: <code>{payload}</code>")
            await send_message(settings.admin_chat_id, "\n".join(lines))

        elif msg_type == "takeover_found":
            subdomains = job_data.get("subdomains", [])
            lines = [
                f"🚨 <b>Subdomain Takeover!</b>\n"
                f"Domain: {_e(job_data.get('domain', ''))}"
            ]
            for sub in subdomains[:5]:
                lines.append(f"• <code>{_e(sub)}</code>")
            await send_message(settings.admin_chat_id, "\n".join(lines))

        elif msg_type == "secrets_found":
            secrets = job_data.get("secrets", [])
            lines = [
                f"🔑 <b>Secrets Found!</b>\n"
                f"Domain: {_e(job_data.get('domain', ''))}"
            ]
            for s in secrets[:3]:
                secret_type = _e(s.get("type", "unknown"), max_len=40)
                lines.append(f"• Type: {secret_type}")
            await send_message(settings.admin_chat_id, "\n".join(lines))

        elif msg_type == "high_priority_urls":
            lines = [
                f"🎯 <b>High-Priority URLs</b>\n"
                f"Domain: {_e(job_data.get('domain', ''))}"
            ]
            for item in job_data.get("urls", [])[:5]:
                url = _e(item.get("url", ""), max_len=80)
                score = _e(item.get("score", "?"), max_len=5)
                lines.append(f"• [{score}] {url}")
            await send_message(settings.admin_chat_id, "\n".join(lines))

        else:
            logger.warning("Unknown notification type", type=msg_type)


async def main():
    worker = NotifyWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())