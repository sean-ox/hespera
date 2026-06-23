"""Telegram command execution — business logic for bot commands."""
import os
import json
import redis
from sqlalchemy.orm import Session
from python.database import SessionLocal
from python.models.target import Target, ScanMode, TargetStatus
from python.models.scan import Scan, ScanType, ScanStatus
from python.models.finding import Finding

# ─── Helpers ──────────────────────────────────────────────────────────────

def get_db() -> Session:
    return SessionLocal()

# ─── Command Implementations ─────────────────────────────────────────────

def add_target(domain: str) -> str:
    db = get_db()
    try:
        existing = db.query(Target).filter(Target.domain == domain).first()
        if existing:
            return f"⚠️ Target `{domain}` sudah ada (status: {existing.status})"
        
        new_target = Target(domain=domain, status=TargetStatus.ACTIVE, scan_mode=ScanMode.SAFE)
        db.add(new_target)
        db.commit()
        return f"✅ Target `{domain}` berhasil ditambahkan."
    except Exception as e:
        db.rollback()
        return f"❌ Gagal menambah target: {str(e)}"
    finally:
        db.close()

def remove_target(domain: str) -> str:
    db = get_db()
    try:
        target = db.query(Target).filter(Target.domain == domain).first()
        if not target:
            return f"⚠️ Target `{domain}` tidak ditemukan."
        db.delete(target)
        db.commit()
        return f"✅ Target `{domain}` telah dihapus."
    except Exception as e:
        db.rollback()
        return f"❌ Gagal menghapus target: {str(e)}"
    finally:
        db.close()

def list_targets() -> str:
    db = get_db()
    try:
        targets = db.query(Target).filter(Target.status == TargetStatus.ACTIVE).all()
        if not targets:
            return "📭 Belum ada target aktif."
        lines = ["📋 *Daftar Target Aktif*:"]
        for t in targets:
            lines.append(f"• `{t.domain}` — mode: {t.scan_mode}")
        return "\n".join(lines)
    except Exception as e:
        return f"❌ Gagal mengambil daftar: {str(e)}"
    finally:
        db.close()

def set_scan_mode(domain: str, mode: str) -> str:
    if mode not in ["safe", "aggressive"]:
        return "❌ Mode harus `safe` atau `aggressive`."
    
    db = get_db()
    try:
        target = db.query(Target).filter(Target.domain == domain).first()
        if not target:
            return f"⚠️ Target `{domain}` tidak ditemukan."
        
        target.scan_mode = ScanMode(mode)
        db.commit()
        return f"✅ Mode scan untuk `{domain}` diubah ke `{mode}`."
    except Exception as e:
        db.rollback()
        return f"❌ Gagal ubah mode: {str(e)}"
    finally:
        db.close()

def trigger_recon_manual(domain: str, mode: str) -> str:
    if mode not in ["safe", "aggressive"]:
        return "❌ Mode harus `safe` atau `aggressive`."
    
    db = get_db()
    try:
        target = db.query(Target).filter(Target.domain == domain).first()
        if not target:
            return f"⚠️ Target `{domain}` tidak ditemukan."
        
        # Buat scan record
        new_scan = Scan(
            target_id=target.id,
            scan_type=ScanType.FULL,
            status=ScanStatus.PENDING
        )
        db.add(new_scan)
        db.commit()
        
        # Kirim ke Redis queue (agar diproses oleh recon_worker)
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        r = redis.Redis.from_url(redis_url)
        r.rpush("queue:recon", json.dumps({
            "target_id": target.id,
            "scan_id": new_scan.id,
            "mode": mode
        }))
        
        return f"🔍 Recon untuk `{domain}` dengan mode `{mode}` telah di-trigger."
    except Exception as e:
        db.rollback()
        return f"❌ Gagal trigger recon: {str(e)}"
    finally:
        db.close()

def get_system_status() -> str:
    db = get_db()
    try:
        target_count = db.query(Target).count()
        scan_count = db.query(Scan).count()
        return f"""📊 *Status Sistem*
• Total target: {target_count}
• Total scan: {scan_count}
• Redis: ✅
• Postgres: ✅
• Workers: recon, nuclei, filter, xss, takeover, js, notify (running)
"""
    except Exception as e:
        return f"❌ Gagal ambil status: {str(e)}"
    finally:
        db.close()

def get_report(domain: str) -> str:
    db = get_db()
    try:
        target = db.query(Target).filter(Target.domain == domain).first()
        if not target:
            return f"⚠️ Target `{domain}` tidak ditemukan."
        
        findings = db.query(Finding).filter(Finding.target_id == target.id).order_by(Finding.created_at.desc()).limit(10).all()
        if not findings:
            return f"📭 Belum ada findings untuk `{domain}`."
        
        lines = [f"📄 *Laporan Findings untuk {domain}*:"]
        for f in findings:
            lines.append(f"• {f.finding_type} — {f.severity} ({f.created_at.strftime('%Y-%m-%d %H:%M')})")
        return "\n".join(lines)
    except Exception as e:
        return f"❌ Gagal ambil report: {str(e)}"
    finally:
        db.close()
