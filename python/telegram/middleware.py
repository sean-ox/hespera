"""Telegram bot middleware for authentication and rate limiting."""
import time
from typing import Dict, Callable, Awaitable, Any
from functools import wraps

from telegram import Update
from telegram.ext import ContextTypes

from python.settings import load_settings
from python.redis_client import redis_client
from python.utils.logging_config import get_logger

settings = load_settings()
logger = get_logger(__name__)

# Simple in-memory rate limiter (use Redis for production)
_rate_limit_cache: Dict[str, list] = {}

# ===================== ADMIN CHECK =====================
def is_admin(chat_id: int) -> bool:
    """Check if a given chat_id is the configured admin."""
    return chat_id == settings.admin_chat_id

# ===================== DECORATORS =====================
def require_admin(func: Callable) -> Callable:
    """Decorator to restrict command to admin only."""
    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Any:
        if not update.effective_chat:
            return
        if not is_admin(update.effective_chat.id):
            logger.warning(
                "Unauthorized access attempt",
                chat_id=update.effective_chat.id,
                command=func.__name__
            )
            await update.message.reply_text("❌ Unauthorized. You are not the admin.")
            return
        return await func(update, context)
    return wrapper


def rate_limit(limit_per_minute: int = 10):
    """Decorator to limit command frequency per chat."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE) -> Any:
            if not update.effective_chat:
                return
            chat_id = update.effective_chat.id
            now = time.time()
            
            # Use Redis in production, fallback to dict
            try:
                key = f"rate_limit:{chat_id}:{func.__name__}"
                history = await redis_client.cache_get(key)
                if history:
                    timestamps = [float(t) for t in history.split(',')]
                else:
                    timestamps = []
                
                # Remove old timestamps
                cutoff = now - 60
                timestamps = [t for t in timestamps if t > cutoff]
                
                if len(timestamps) >= limit_per_minute:
                    await update.message.reply_text(
                        f"⏳ Rate limit exceeded. Max {limit_per_minute} commands per minute."
                    )
                    return
                
                timestamps.append(now)
                await redis_client.cache_set(
                    key, ','.join(str(t) for t in timestamps), ttl=60
                )
            except Exception as e:
                # Fallback to in-memory rate limiting
                logger.debug("Redis rate limit fallback", error=str(e))
                key = f"{chat_id}:{func.__name__}"
                if key not in _rate_limit_cache:
                    _rate_limit_cache[key] = []
                timestamps = [t for t in _rate_limit_cache[key] if t > now - 60]
                if len(timestamps) >= limit_per_minute:
                    await update.message.reply_text(
                        f"⏳ Rate limit exceeded. Max {limit_per_minute} commands per minute."
                    )
                    return
                timestamps.append(now)
                _rate_limit_cache[key] = timestamps
            
            return await func(update, context)
        return wrapper
    return decorator
