"""Telegram bot initialization and command registration."""
from telegram.ext import Application, CommandHandler, CallbackContext
from telegram import Update

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


def create_bot_app() -> Application:
    """Create and configure the Telegram bot application."""
    app = Application.builder().token(settings.telegram_bot_token).build()
    
    # Register commands (with auth where needed)
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("add", add_command))
    app.add_handler(CommandHandler("remove", remove_command))
    app.add_handler(CommandHandler("list", list_command))
    app.add_handler(CommandHandler("set_mode", set_mode_command))
    app.add_handler(CommandHandler("recon", recon_command))
    app.add_handler(CommandHandler("status", status_command))
    app.add_handler(CommandHandler("report", report_command))
    
    logger.info("Telegram bot handlers registered")
    return app


async def send_message(chat_id: int, text: str, parse_mode: str = "HTML") -> bool:
    """Send a message to a Telegram chat."""
    app = create_bot_app()
    try:
        await app.bot.send_message(chat_id=chat_id, text=text, parse_mode=parse_mode)
        return True
    except Exception as e:
        logger.error("Failed to send Telegram message", error=str(e))
        return False