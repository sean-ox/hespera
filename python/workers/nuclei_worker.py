"""Nuclei worker - runs vulnerability scanning on collected URLs."""
import asyncio
from typing import List

from python.workers.base import BaseWorker
from python.database import db_manager
from python.redis_client import redis_client
from python.models.scan import Scan
from python.models.finding import Finding, FindingType, Severity
from python.services.deduplicator import Deduplicator
from python.utils.process import run_command_safe
from python.utils.logging_config import get_logger
from python.settings import load_settings

settings = load_settings()
logger = get_logger(__name__)

DEDUPLICATOR = Deduplicator(redis_client)


class NucleiWorker(BaseWorker):
    """Worker that runs nuclei vulnerability scanning."""
    
    def __init__(self):
        super().__init__("queue:nuclei", "nuclei_worker")
    
    async def process_job(self, job_data: dict) -> None:
        """Run nuclei on provided URLs."""
        scan_id = job_data.get("scan_id")
        target_id = job_data.get("target_id")
        domain = job_data.get("domain")
        urls = job_data.get("urls", [])
        
        if not urls:
            logger.info("No URLs to scan", domain=domain)
            return
        
        # Write URLs to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for url in urls:
                f.write(url + '\n')
            input_file = f.name
        
        try:
            # Determine severity based on mode (from config)
            severity = "low,medium,high,critical"
            rate_limit = 10
            
            cmd = [
                settings.nuclei_bin,
                "-l", input_file,
                "-severity", severity,
                "-rate-limit", str(rate_limit),
                "-bulk-size", "10",
                "-silent",
                "-json"
            ]
            
            result = await run_command_safe(cmd, timeout_seconds=1800)
            
            if result.stdout:
                findings = []
                for line in result.stdout.strip().split('\n'):
                    if not line.strip():
                        continue
                    
                    import json
                    try:
                        data = json.loads(line)
                        finding_data = {
                            "url": data.get("host", ""),
                            "template_id": data.get("template-id", ""),
                            "template_name": data.get("template", ""),
                            "matched_at": data.get("matched-at", ""),
                            "extracted_results": data.get("extracted-results", []),
                            "info": data.get("info", {})
                        }
                        
                        severity_str = data.get("info", {}).get("severity", "info").lower()
                        severity_map = {
                            "info": Severity.INFO,
                            "low": Severity.LOW,
                            "medium": Severity.MEDIUM,
                            "high": Severity.HIGH,
                            "critical": Severity.CRITICAL
                        }
                        severity_enum = severity_map.get(severity_str, Severity.INFO)
                        
                        # Deduplicate
                        if not await DEDUPLICATOR.is_duplicate("vulnerability", finding_data):
                            findings.append({
                                "scan_id": scan_id,
                                "target_id": target_id,
                                "finding_type": FindingType.VULNERABILITY,
                                "finding_data": finding_data,
                                "severity": severity_enum,
                                "is_new": True,
                                "dedup_hash": DEDUPLICATOR.compute_hash("vulnerability", finding_data)
                            })
                    except json.JSONDecodeError:
                        continue
                
                if findings:
                    async with db_manager.session() as session:
                        for f in findings:
                            finding = Finding(**f)
                            session.add(finding)
                        await session.commit()
                    
                    logger.info(
                        "Nuclei findings saved",
                        domain=domain,
                        count=len(findings),
                        critical=sum(1 for f in findings if f["severity"] == Severity.CRITICAL),
                        high=sum(1 for f in findings if f["severity"] == Severity.HIGH)
                    )
                    
                    # Send notification for critical/high findings
                    critical_high = [f for f in findings if f["severity"] in (Severity.CRITICAL, Severity.HIGH)]
                    if critical_high:
                        await redis_client.enqueue("queue:notify", {
                            "type": "vulnerabilities_found",
                            "domain": domain,
                            "vulnerabilities": [
                                {
                                    "template": f["finding_data"].get("template_id", "unknown"),
                                    "url": f["finding_data"].get("url", ""),
                                    "severity": f["severity"].value
                                }
                                for f in critical_high[:10]
                            ]
                        })
        
        finally:
            import os
            os.unlink(input_file)


async def main():
    worker = NucleiWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())