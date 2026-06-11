"""Recon worker - runs subdomain enumeration and URL collection."""
import asyncio
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Set

from python.workers.base import BaseWorker
from python.database import db_manager
from python.redis_client import redis_client
from python.models.target import Target, ScanMode, TargetStatus
from python.models.scan import Scan, ScanStatus, ScanType
from python.models.finding import Finding, FindingType, Severity
from python.services.scope import ScopeValidator
from python.services.deduplicator import Deduplicator
from python.utils.process import run_command_safe
from python.utils.validators import is_valid_subdomain
from python.utils.logging_config import get_logger
from python.settings import load_settings

settings = load_settings()
logger = get_logger(__name__)

OUTPUT_BASE = Path("/app/output")
OUTPUT_BASE.mkdir(exist_ok=True, parents=True)

SCOPE_VALIDATOR = ScopeValidator(settings.scope_file)
DEDUPLICATOR = Deduplicator(redis_client)


async def enqueue_recon(domain: str, mode: str, triggered_by: Optional[int] = None) -> str:
    """Enqueue a recon job for a domain."""
    job_data = {
        "domain": domain,
        "mode": mode,
        "triggered_by": triggered_by,
        "timestamp": datetime.utcnow().isoformat()
    }
    return await redis_client.enqueue("queue:recon", job_data)


class ReconWorker(BaseWorker):
    """Worker that performs recon on a target domain."""
    
    def __init__(self):
        super().__init__("queue:recon", "recon_worker")
        self.semaphore = asyncio.Semaphore(settings.max_concurrent_recon)
        self.timeout = settings.recon_timeout_seconds
    
    async def process_job(self, job_data: dict) -> None:
        """Execute recon for a domain."""
        domain = job_data.get("domain")
        mode = job_data.get("mode", "safe")
        triggered_by = job_data.get("triggered_by")
        
        async with self.semaphore:
            await self._run_recon(domain, mode, triggered_by)
    
    async def _run_recon(self, domain: str, mode: str, triggered_by: Optional[int]) -> None:
        """Orchestrate the recon process for a single domain."""
        start_time = datetime.utcnow()
        scan_id = None
        
        try:
            # Get target from database
            async with db_manager.session() as session:
                from sqlalchemy import select
                stmt = select(Target).where(
                    Target.domain == domain,
                    Target.status == TargetStatus.ACTIVE
                )
                result = await session.execute(stmt)
                target = result.scalar_one_or_none()
                
                if not target:
                    logger.warning("Target not found or inactive", domain=domain)
                    return
                
                # Create scan record
                scan = Scan(
                    target_id=target.id,
                    scan_type=ScanType.FULL,
                    status=ScanStatus.RUNNING,
                    started_at=start_time
                )
                session.add(scan)
                await session.flush()
                scan_id = scan.id
                await session.commit()
            
            # Create output directory for this domain
            domain_dir = OUTPUT_BASE / domain
            domain_dir.mkdir(exist_ok=True)
            
            # Step 1: Subdomain enumeration
            subdomains = await self._enumerate_subdomains(domain, domain_dir)
            
            # Step 2: Filter by scope
            in_scope_subs = SCOPE_VALIDATOR.filter_scope(subdomains)
            logger.info("Scope filter results", domain=domain, total=len(subdomains), in_scope=len(in_scope_subs))
            
            # Step 3: Probe live hosts
            live_hosts = await self._probe_hosts(in_scope_subs, domain_dir, mode)
            
            # Step 4: Collect URLs
            urls = await self._collect_urls(live_hosts, domain_dir, mode)
            
            # ========== ENHANCEMENT: Push raw URLs & subdomains to filter pipeline ==========
            if urls:
                await redis_client.enqueue("queue:raw_urls", {
                    "scan_id": scan_id,
                    "target_id": target.id,
                    "domain": domain,
                    "urls": urls[:10000],          # limit to 10k URLs per scan
                    "subdomains": in_scope_subs[:5000],
                    "mode": mode
                })
                logger.info("Raw URLs enqueued for filtering", domain=domain, count=len(urls[:10000]))
            
            # Step 5: Save findings to database (original behavior)
            await self._save_findings(scan_id, domain, in_scope_subs, urls)
            
            # Step 6: Update scan record as completed
            duration = (datetime.utcnow() - start_time).total_seconds()
            async with db_manager.session() as session:
                scan = await session.get(Scan, scan_id)
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.duration_seconds = int(duration)
                    
                    target = await session.get(Target, target.id)
                    if target:
                        target.last_recon_at = datetime.utcnow()
                    
                    await session.commit()
            
            logger.info("Recon completed", domain=domain, duration=duration, subdomains=len(in_scope_subs))
            
            # Send basic notification (summary)
            await redis_client.enqueue("queue:notify", {
                "type": "recon_complete",
                "domain": domain,
                "subdomain_count": len(in_scope_subs),
                "url_count": len(urls),
                "triggered_by": triggered_by
            })
            
        except Exception as e:
            logger.exception("Recon failed", domain=domain, error=str(e))
            if scan_id:
                async with db_manager.session() as session:
                    scan = await session.get(Scan, scan_id)
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        await session.commit()
            await redis_client.enqueue("queue:notify", {
                "type": "recon_failed",
                "domain": domain,
                "error": str(e)[:200],
                "triggered_by": triggered_by
            })
    
    async def _enumerate_subdomains(self, domain: str, output_dir: Path) -> List[str]:
        """Run subfinder and assetfinder to enumerate subdomains."""
        all_subs: Set[str] = set()
        
        # Run subfinder
        cmd = [settings.subfinder_bin, "-d", domain, "-silent"]
        result = await run_command_safe(cmd, timeout_seconds=300)
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    all_subs.add(line.strip().lower())
        
        # Run assetfinder
        cmd = [settings.assetfinder_bin, "--subs-only", domain]
        result = await run_command_safe(cmd, timeout_seconds=300)
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    all_subs.add(line.strip().lower())
        
        # Write to file
        subs_file = output_dir / "all_subs.txt"
        with open(subs_file, 'w') as f:
            for sub in sorted(all_subs):
                f.write(sub + '\n')
        
        logger.info("Subdomain enumeration complete", domain=domain, count=len(all_subs))
        return list(all_subs)
    
    async def _probe_hosts(self, subdomains: List[str], output_dir: Path, mode: str) -> List[str]:
        """Run httpx to probe live hosts."""
        if not subdomains:
            return []
        
        rate_limit = 5 if mode == "safe" else 20
        input_file = output_dir / "subs_to_probe.txt"
        with open(input_file, 'w') as f:
            for sub in subdomains:
                f.write(sub + '\n')
        
        cmd = [
            settings.httpx_bin,
            "-l", str(input_file),
            "-silent",
            "-status-code",
            "-rate-limit", str(rate_limit),
            "-timeout", "10"
        ]
        result = await run_command_safe(cmd, timeout_seconds=600)
        
        live_hosts = []
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split(' ')
                    if parts:
                        url = parts[0]
                        if url.startswith('http'):
                            live_hosts.append(url)
        
        output_file = output_dir / "live_hosts.txt"
        with open(output_file, 'w') as f:
            for url in live_hosts:
                f.write(url + '\n')
        
        logger.info("Host probing complete", domain=output_dir.name, count=len(live_hosts))
        return live_hosts
    
    async def _collect_urls(self, live_hosts: List[str], output_dir: Path, mode: str) -> List[str]:
        """Collect URLs using gau, waybackurls, and katana."""
        all_urls: Set[str] = set()
        
        hosts_to_scan = live_hosts[:20] if mode == "safe" else live_hosts[:50]
        
        async def run_tool(host: str):
            # gau
            cmd = [settings.gau_bin, host]
            result = await run_command_safe(cmd, timeout_seconds=120)
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        all_urls.add(line.strip())
            # waybackurls
            cmd = [settings.waybackurls_bin, host]
            result = await run_command_safe(cmd, timeout_seconds=120)
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        all_urls.add(line.strip())
        
        sem = asyncio.Semaphore(5)
        async def limited_task(host):
            async with sem:
                await run_tool(host)
        
        await asyncio.gather(*[limited_task(h) for h in hosts_to_scan])
        
        # katana for aggressive mode
        if mode == "aggressive" and live_hosts:
            input_file = output_dir / "live_hosts.txt"
            cmd = [
                settings.katana_bin,
                "-list", str(input_file),
                "-depth", "2",
                "-silent",
                "-rate-limit", "10"
            ]
            result = await run_command_safe(cmd, timeout_seconds=600)
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        all_urls.add(line.strip())
        
        output_file = output_dir / "all_urls.txt"
        with open(output_file, 'w') as f:
            for url in sorted(all_urls):
                f.write(url + '\n')
        
        logger.info("URL collection complete", domain=output_dir.name, count=len(all_urls))
        return list(all_urls)
    
    async def _save_findings(self, scan_id: int, domain: str, subdomains: List[str], urls: List[str]) -> None:
        """Save findings to database with deduplication."""
        async with db_manager.session() as session:
            scan = await session.get(Scan, scan_id)
            if not scan:
                return
            target_id = scan.target_id
            
            # Save subdomains
            for sub in subdomains:
                if not is_valid_subdomain(sub):
                    continue
                finding_data = {"subdomain": sub}
                if await DEDUPLICATOR.is_duplicate("subdomain", finding_data):
                    continue
                finding = Finding(
                    scan_id=scan_id,
                    target_id=target_id,
                    finding_type=FindingType.SUBDOMAIN,
                    finding_data=finding_data,
                    severity=Severity.INFO,
                    is_new=True,
                    dedup_hash=DEDUPLICATOR.compute_hash("subdomain", finding_data)
                )
                session.add(finding)
            
            # Save URLs (limit 5000)
            for url in urls[:5000]:
                finding_data = {"url": url}
                if await DEDUPLICATOR.is_duplicate("url", finding_data):
                    continue
                finding = Finding(
                    scan_id=scan_id,
                    target_id=target_id,
                    finding_type=FindingType.URL,
                    finding_data=finding_data,
                    severity=Severity.INFO,
                    is_new=True,
                    dedup_hash=DEDUPLICATOR.compute_hash("url", finding_data)
                )
                session.add(finding)
            
            await session.commit()
            logger.info("Findings saved", domain=domain, subdomains=len(subdomains), urls=min(len(urls), 5000))


async def main():
    worker = ReconWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())