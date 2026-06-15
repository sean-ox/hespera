"""Subdomain Takeover Worker - uses subzy to detect dangling CNAMEs."""
import asyncio
import os
import tempfile
import json
from typing import List

from python.workers.base import BaseWorker
from python.redis_client import redis_client
from python.database import db_manager
from python.models.scan import Scan
from python.models.finding import Finding, FindingType, Severity
from python.services.deduplicator import Deduplicator
from python.utils.process import run_command_safe
from python.utils.logging_config import get_logger
from python.settings import load_settings

settings = load_settings()
logger = get_logger(__name__)
DEDUPLICATOR = Deduplicator(redis_client)


class TakeoverWorker(BaseWorker):
    """Detect subdomain takeover using subzy."""
    
    def __init__(self):
        super().__init__("queue:takeover", "takeover_worker")
        self.semaphore = asyncio.Semaphore(2)
    
    async def process_job(self, job_data: dict) -> None:
        scan_id = job_data.get("scan_id")
        domain = job_data.get("domain")
        subdomains = job_data.get("subdomains", [])
        
        if not subdomains:
            return
        
        async with self.semaphore:
            await self._scan_takeover(scan_id, domain, subdomains)
    
    async def _scan_takeover(self, scan_id: int, domain: str, subdomains: List[str]) -> None:
        """Run subzy to check for takeover possibilities."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for sub in subdomains:
                f.write(sub + '\n')
            input_file = f.name
        
        try:
            cmd = [
                settings.subzy_bin,
                "run",
                "--targets", input_file,
                "--concurrency", "10",
                "--hide_fails",
                "--timeout", "5",
                "--output", "/dev/stdout"
            ]
            result = await run_command_safe(cmd, timeout_seconds=300)
            
            if result.stdout:
                findings = self._parse_subzy_output(result.stdout, scan_id, domain)
                if findings:
                    await self._save_findings(findings)
                    # Notify if any takeover found
                    if findings:
                        await redis_client.enqueue("queue:notify", {
                            "type": "takeover_found",
                            "domain": domain,
                            "subdomains": [f["finding_data"].get("subdomain") for f in findings]
                        })
        finally:
            os.unlink(input_file)
    
    def _parse_subzy_output(self, output: str, scan_id: int, domain: str) -> List[dict]:
        """Parse subzy text output (or JSON if available). Subzy default is human-readable."""
        findings = []
        lines = output.split('\n')
        for line in lines:
            if "VULNERABLE" in line or "TAKEOVER" in line:
                # Example: "[VULNERABLE] sub.example.com [CNAME: service.herokuapp.com]"
                parts = line.split()
                subdomain = None
                for part in parts:
                    if '.' in part and domain in part:
                        subdomain = part.strip('[]')
                        break
                if subdomain:
                    finding_data = {
                        "subdomain": subdomain,
                        "evidence": line.strip(),
                        "tool": "subzy"
                    }
                    dedup_hash = DEDUPLICATOR.compute_hash("takeover", finding_data)
                    findings.append({
                        "scan_id": scan_id,
                        "target_id": None,
                        "finding_type": FindingType.VULNERABILITY,
                        "finding_data": finding_data,
                        "severity": Severity.HIGH,  # takeover is high/critical
                        "is_new": True,
                        "dedup_hash": dedup_hash
                    })
        return findings
    
    async def _save_findings(self, findings: List[dict]) -> None:
        if not findings:
            return
        async with db_manager.session() as session:
            scan = await session.get(Scan, findings[0]["scan_id"])
            if not scan:
                return
            target_id = scan.target_id
            for f in findings:
                f["target_id"] = target_id
                session.add(Finding(**f))
            await session.commit()
            logger.info("Saved takeover findings", count=len(findings))


async def main():
    worker = TakeoverWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())