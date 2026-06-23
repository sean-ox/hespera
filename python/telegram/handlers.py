"""Telegram command handlers."""
from telegram import Update
from telegram.ext import ContextTypes

from python.models.target import Target, ScanMode, TargetStatus
from python.services.reporter import Reporter
from python.services.scope import ScopeValidator
from python.workers.recon_worker import enqueue_recon
from python.database import db_manager
from python.settings import load_settings
from python.telegram.middleware import require_admin, rate_limit
from python.utils.validators import is_valid_domain, sanitize_domain
from python.utils.logging_config import get_logger

settings = load_settings()
logger = get_logger(__name__)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start command."""
    await update.message.reply_text(
        "🤖 <b>Bounty Bot v2.0</b>\n\n"
        "Bug Bounty Automation Platform\n\n"
        "<b>Commands:</b>\n"
        "/add domain.com - Add target\n"
        "/remove domain.com - Remove target\n"
        "/list - List all targets\n"
        "/set_mode domain.com safe|aggressive - Change scan mode\n"
        "/recon domain.com [mode] - Run manual recon\n"
        "/status - System status\n"
        "/report domain.com - Latest report\n"
        "/help - Show this help\n",
        parse_mode="HTML"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help command."""
    await start_command(update, context)


@require_admin
@rate_limit(limit_per_minute=5)
async def add_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /add command."""
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /add domain.com")
        return

    domain = context.args[0].lower().strip()

    if not is_valid_domain(domain):
        await update.message.reply_text(
            f"❌ Invalid domain format: {domain}\n"
            "Domain must follow standard format (e.g., example.com)"
        )
        return

    domain = sanitize_domain(domain)

    async with db_manager.session() as session:
        from sqlalchemy import select
        stmt = select(Target).where(Target.domain == domain)
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing and existing.status != TargetStatus.REMOVED:
            await update.message.reply_text(f"⚠️ Target {domain} already exists")
            return

        target = Target(
            domain=domain,
            scan_mode=ScanMode.SAFE,
            created_by_chat_id=update.effective_chat.id,
            status=TargetStatus.ACTIVE
        )
        session.add(target)
        await session.commit()

    logger.info("Target added", domain=domain, admin=update.effective_chat.id)
    await update.message.reply_text(f"✅ Target {domain} added (mode: safe)")


@require_admin
async def remove_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /remove command."""
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /remove domain.com")
        return

    domain = context.args[0].lower().strip()

    async with db_manager.session() as session:
        from sqlalchemy import select
        stmt = select(Target).where(Target.domain == domain)
        result = await session.execute(stmt)
        target = result.scalar_one_or_none()

        if not target or target.status == TargetStatus.REMOVED:
            await update.message.reply_text(f"❌ Target {domain} not found")
            return

        target.status = TargetStatus.REMOVED
        await session.commit()

    logger.info("Target removed", domain=domain)
    await update.message.reply_text(f"🗑 Target {domain} removed")


@require_admin
async def list_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /list command."""
    async with db_manager.session() as session:
        from sqlalchemy import select
        stmt = select(Target).where(Target.status == TargetStatus.ACTIVE)
        result = await session.execute(stmt)
        targets = result.scalars().all()

    if not targets:
        await update.message.reply_text("No active targets.")
        return

    lines = ["📋 <b>Active Targets</b>:"]
    for t in targets:
        lines.append(f"• <code>{t.domain}</code> (mode: {t.scan_mode.value})")

    await update.message.reply_text("\n".join(lines), parse_mode="HTML")


@require_admin
async def set_mode_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /set_mode command."""
    if len(context.args) != 2:
        await update.message.reply_text("Usage: /set_mode domain.com safe|aggressive")
        return

    domain = context.args[0].lower().strip()
    mode_str = context.args[1].lower().strip()

    try:
        mode = ScanMode(mode_str)
    except ValueError:
        await update.message.reply_text("Mode must be 'safe' or 'aggressive'")
        return

    async with db_manager.session() as session:
        from sqlalchemy import select
        stmt = select(Target).where(Target.domain == domain, Target.status == TargetStatus.ACTIVE)
        result = await session.execute(stmt)
        target = result.scalar_one_or_none()

        if not target:
            await update.message.reply_text(f"❌ Target {domain} not found")
            return

        target.scan_mode = mode
        await session.commit()

    await update.message.reply_text(f"✅ Mode for {domain} set to {mode_str}")


@require_admin
@rate_limit(limit_per_minute=2)
async def recon_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /recon command - trigger manual recon."""
    args = context.args
    if len(args) < 1:
        await update.message.reply_text("Usage: /recon domain.com [mode]")
        return

    domain = args[0].lower().strip()

    mode_override = None
    if len(args) > 1 and args[1].lower() in ["safe", "aggressive"]:
        mode_override = args[1].lower()

    async with db_manager.session() as session:
        from sqlalchemy import select
        stmt = select(Target).where(Target.domain == domain, Target.status == TargetStatus.ACTIVE)
        result = await session.execute(stmt)
        target = result.scalar_one_or_none()

        if not target:
            await update.message.reply_text(f"❌ Target {domain} not found")
            return

        final_mode = ScanMode(mode_override) if mode_override else target.scan_mode

    job_id = await enqueue_recon(domain, final_mode.value, triggered_by=update.effective_chat.id)

    await update.message.reply_text(
        f"⏳ Recon for {domain} queued (mode: {final_mode.value})\n"
        f"Job ID: {job_id}"
    )


@require_admin
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /status command - system health."""
    async with db_manager.session() as session:
        from sqlalchemy import select, func
        stmt = select(func.count()).select_from(Target).where(Target.status == TargetStatus.ACTIVE)
        target_count = await session.execute(stmt)
        target_count = target_count.scalar()

    try:
        from python.redis_client import redis_client
        pending = await redis_client.get_queue_length("queue:recon")
    except Exception:
        pending = "unknown"

    await update.message.reply_text(
        f"🖥 <b>System Status</b>\n"
        f"Active targets: {target_count}\n"
        f"Pending recon jobs: {pending}\n"
        f"Scan mode: Parallel (max {settings.max_concurrent_recon})\n"
        f"Schedule: Every {settings.schedule_interval_minutes} minutes\n",
        parse_mode="HTML"
    )


@require_admin
async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /report command - show latest findings."""
    if len(context.args) != 1:
        await update.message.reply_text("Usage: /report domain.com")
        return

    domain = context.args[0].lower().strip()

    reporter = Reporter(db_manager)
    report = await reporter.get_latest_report(domain)

    if not report:
        await update.message.reply_text(f"No recon data found for {domain}")
        return

    await update.message.reply_text(report, parse_mode="HTML")


# ===================== FUNGSI UNTUK WEBHOOK =====================

def process_telegram_command(chat_id: int, text: str) -> str:
    """
    Sinkron wrapper untuk memproses perintah dari webhook.
    Dipanggil oleh main.py saat menerima POST /webhook.
    """
    from python.telegram.middleware import is_admin
    from python.services.telegram_commands import (
        add_target,
        remove_target,
        list_targets,
        set_scan_mode,
        trigger_recon_manual,
        get_system_status,
        get_report,
    )

    if not is_admin(chat_id):
        return "⛔ Anda tidak memiliki akses ke bot ini."

    if not text.startswith("/"):
        return "❌ Kirim perintah dengan awalan '/'"

    parts = text.strip().split()
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd in ["/start", "/help"]:
        return get_help_text()

    if cmd == "/add" and args:
        return add_target(args[0])
    if cmd == "/remove" and args:
        return remove_target(args[0])
    if cmd == "/list":
        return list_targets()
    if cmd == "/set_mode" and len(args) >= 2:
        return set_scan_mode(args[0], args[1])
    if cmd == "/recon" and args:
        domain = args[0]
        mode = args[1] if len(args) > 1 else "safe"
        return trigger_recon_manual(domain, mode)
    if cmd == "/status":
        return get_system_status()
    if cmd == "/report" and args:
        return get_report(args[0])

    return "❌ Perintah tidak dikenal. Ketik /help untuk daftar."


def get_help_text() -> str:
    return """🤖 *Hespera Bot — Daftar Perintah*

/add <domain>       ➕ Tambah target baru
/remove <domain>    ❌ Hapus target
/list               📋 Daftar semua target aktif
/set_mode <domain> <mode>  ⚙️ Ubah mode scan (safe/aggressive)
/recon <domain> [mode]  🔍 Trigger recon manual
/status             📊 Status sistem & antrian
/report <domain>    📄 Laporan findings terbaru

*Mode:* safe, aggressive
"""
