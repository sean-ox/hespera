"""XSS Worker - runs dalfox to detect XSS vulnerabilities."""
import asyncio
import json
import tempfile
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


class XSSWorker(BaseWorker):
    """Detect XSS using dalfox."""
    
    def __init__(self):
        super().__init__("queue:xss_candidates", "xss_worker")
        self.semaphore = asyncio.Semaphore(2)  # limit concurrency
    
    async def process_job(self, job_data: dict) -> None:
        """Run dalfox on provided URLs."""
        scan_id = job_data.get("scan_id")
        domain = job_data.get("domain")
        urls = job_data.get("urls", [])
        
        if not urls:
            return
        
        async with self.semaphore:
            await self._scan_xss(scan_id, domain, urls)
    
    async def _scan_xss(self, scan_id: int, domain: str, urls: List[str]) -> None:
        """Execute dalfox against a list of URLs."""
        # Write URLs to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for url in urls:
                f.write(url + '\n')
            input_file = f.name
        
        try:
            # dalfox command: light mode, no browser, output JSON
            cmd = [
                settings.dalfox_bin,
                "file", input_file,
                "--skip-bav",           # skip blind XSS (light)
                "--no-spinner",
                "--silent",
                "--output", "/dev/stdout",
                "--format", "json"
            ]
            result = await run_command_safe(cmd, timeout_seconds=300)
            
            if result.returncode != 0 and result.stderr:
                logger.warning("dalfox error", domain=domain, error=result.stderr[:200])
            
            if result.stdout:
                findings = self._parse_dalfox_output(result.stdout, scan_id, domain)
                if findings:
                    await self._save_findings(findings)
                    # Notify critical/high findings
                    critical_high = [f for f in findings if f["severity"] in (Severity.CRITICAL, Severity.HIGH)]
                    if critical_high:
                        await redis_client.enqueue("queue:notify", {
                            "type": "xss_found",
                            "domain": domain,
                            "findings": [
                                {"url": f["finding_data"].get("url"), "payload": f["finding_data"].get("payload", "")[:100]}
                                for f in critical_high[:5]
                            ]
                        })
        
        finally:
            import os
            os.unlink(input_file)
    
    def _parse_dalfox_output(self, output: str, scan_id: int, domain: str) -> List[dict]:
        """Parse dalfox JSON output and convert to finding dicts."""
        findings = []
        for line in output.split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                # dalfox output example: {"url": "...", "param": "...", "payload": "...", "type": "...", "severity": "high"}
                severity_str = data.get("severity", "medium").lower()
                severity_map = {
                    "info": Severity.INFO,
                    "low": Severity.LOW,
                    "medium": Severity.MEDIUM,
                    "high": Severity.HIGH,
                    "critical": Severity.CRITICAL
                }
                severity = severity_map.get(severity_str, Severity.MEDIUM)
                
                finding_data = {
                    "url": data.get("url", ""),
                    "parameter": data.get("param", ""),
                    "payload": data.get("payload", ""),
                    "type": data.get("type", "reflected"),
                    "evidence": data.get("evidence", ""),
                    "tool": "dalfox"
                }
                dedup_hash = DEDUPLICATOR.compute_hash("xss", finding_data)
                # Check duplicate (optional)
                # if await DEDUPLICATOR.is_duplicate("xss", finding_data): continue
                
                findings.append({
                    "scan_id": scan_id,
                    "target_id": None,  # will be resolved when saving
                    "finding_type": FindingType.VULNERABILITY,
                    "finding_data": finding_data,
                    "severity": severity,
                    "is_new": True,
                    "dedup_hash": dedup_hash
                })
            except json.JSONDecodeError:
                continue
        return findings
    
    async def _save_findings(self, findings: List[dict]) -> None:
        """Save findings to database, resolving target_id from scan."""
        if not findings:
            return
        async with db_manager.session() as session:
            # Get target_id from scan_id (first finding)
            scan = await session.get(Scan, findings[0]["scan_id"])
            if not scan:
                logger.error("Scan not found", scan_id=findings[0]["scan_id"])
                return
            target_id = scan.target_id
            for f in findings:
                f["target_id"] = target_id
                finding = Finding(**f)
                session.add(finding)
            await session.commit()
            logger.info("Saved XSS findings", count=len(findings))


async def main():
    worker = XSSWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())