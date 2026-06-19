"""Telegram bot initialization and command registration."""
from typing import Optional

from telegram.ext import Application, CommandHandler, CallbackContext
from telegram import Bot, Update

from python.settings import load_settings
from python.telegram.handlers import (
    start_command,
    add_command,
    remove_command,
    list_command,
    set_mode_command,
    recon_command,
    status_command,
    report_command,
    help_command,
)
from python.telegram.middleware import require_admin, rate_limit
from python.utils.logging_config import get_logger

settings = load_settings()
logger = get_logger(__name__)

# Module-level singleton: set once by main.py lifespan, read by all workers
_bot_app: Optional[Application] = None
_bot: Optional[Bot] = None


def create_bot_app() -> Application:
    """Create and configure the Telegram bot application.

    Called ONCE during orchestrator startup (lifespan).
    Stores the Application in the module-level singleton so that
    send_message() can reuse the already-initialised bot connection.
    """
    global _bot_app, _bot

    app = Application.builder().token(settings.telegram_bot_token).build()

    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("add", add_command))
    app.add_handler(CommandHandler("remove", remove_command))
    app.add_handler(CommandHandler("list", list_command))
    app.add_handler(CommandHandler("set_mode", set_mode_command))
    app.add_handler(CommandHandler("recon", recon_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("report", report_command))

    _bot_app = app
    _bot = app.bot

    logger.info("Telegram bot handlers registered")
    return app


async def send_message(chat_id: int, text: str, parse_mode: str = "HTML") -> bool:
    """Send a Telegram message using the already-initialised singleton bot.

    Workers (notify_worker, nuclei_worker, xss_worker, etc.) call this
    function. It must NOT create a new Application instance — doing so
    produces an uninitialised bot that raises RuntimeError on every send.

    Falls back to a one-shot Bot() if the singleton was never set
    (e.g. when a worker runs in a separate process without the orchestrator).
    """
    global _bot

    try:
        if _bot is None:
            # Worker process: orchestrator singleton not available.
            # Create a lightweight Bot directly (no polling, no handlers).
            _bot = Bot(token=settings.telegram_bot_token)

        await _bot.send_message(chat_id=chat_id, text=text, parse_mode=parse_mode)
        return True
    except Exception as e:
        logger.error("Failed to send Telegram message", error=str(e))
        return False