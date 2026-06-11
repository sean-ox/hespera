"""JavaScript Worker - extract endpoints and secrets from JS files."""
import asyncio
import tempfile
import json
import re
from pathlib import Path
from typing import List, Dict

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


class JsWorker(BaseWorker):
    """Extract JS endpoints and secrets using jsluice and trufflehog."""
    
    def __init__(self):
        super().__init__("queue:js_endpoints", "js_worker")
        self.semaphore = asyncio.Semaphore(3)
    
    async def process_job(self, job_data: dict) -> None:
        scan_id = job_data.get("scan_id")
        domain = job_data.get("domain")
        js_urls = job_data.get("urls", [])
        
        if not js_urls:
            return
        
        async with self.semaphore:
            await self._process_js_files(scan_id, domain, js_urls)
    
    async def _process_js_files(self, scan_id: int, domain: str, js_urls: List[str]) -> None:
        """Download JS files (or just URLs) and extract endpoints + secrets."""
        # For performance, we don't download full JS; use jsluice directly on URLs
        # jsluice can accept URLs and parse remotely.
        findings = []
        
        # 1. Use jsluice to extract endpoints from JS URLs
        if settings.jsluice_bin:
            endpoints = await self._run_jsluice(js_urls)
            for endpoint in endpoints:
                finding_data = {
                    "url": endpoint,
                    "source_js": "jsluice",
                    "type": "endpoint"
                }
                dedup_hash = DEDUPLICATOR.compute_hash("js_endpoint", finding_data)
                findings.append({
                    "scan_id": scan_id,
                    "target_id": None,
                    "finding_type": FindingType.URL,  # or custom type
                    "finding_data": finding_data,
                    "severity": Severity.INFO,
                    "is_new": True,
                    "dedup_hash": dedup_hash
                })
        
        # 2. Use trufflehog to find secrets (if trufflehog installed)
        if settings.trufflehog_bin and js_urls:
            secrets = await self._run_trufflehog(js_urls)
            for secret in secrets:
                finding_data = {
                    "file": secret.get("file", ""),
                    "secret": secret.get("secret", "")[:100],
                    "type": secret.get("type", "unknown"),
                    "tool": "trufflehog"
                }
                dedup_hash = DEDUPLICATOR.compute_hash("secret", finding_data)
                findings.append({
                    "scan_id": scan_id,
                    "target_id": None,
                    "finding_type": FindingType.VULNERABILITY,
                    "finding_data": finding_data,
                    "severity": Severity.CRITICAL,
                    "is_new": True,
                    "dedup_hash": dedup_hash
                })
        
        if findings:
            await self._save_findings(findings)
            # Notify critical secrets
            critical_secrets = [f for f in findings if f.get("severity") == Severity.CRITICAL]
            if critical_secrets:
                await redis_client.enqueue("queue:notify", {
                    "type": "secrets_found",
                    "domain": domain,
                    "secrets": [f["finding_data"] for f in critical_secrets[:3]]
                })
    
    async def _run_jsluice(self, urls: List[str]) -> List[str]:
        """Run jsluice urls command to extract endpoints."""
        input_text = "\n".join(urls)
        cmd = [settings.jsluice_bin, "urls"]
        result = await run_command_safe(cmd, input_data=input_text, timeout_seconds=120)
        if result.returncode == 0 and result.stdout:
            # jsluice outputs endpoints per line
            return [line.strip() for line in result.stdout.split('\n') if line.strip() and line.startswith('http')]
        return []
    
    async def _run_trufflehog(self, urls: List[str]) -> List[Dict]:
        """Run trufflehog filesystem on downloaded JS files (or on URLs if supported)."""
        # For simplicity, we assume trufflehog can scan URLs directly? Better to download.
        # Here we download each JS file to a temp dir and scan.
        import aiohttp
        import tempfile
        import os
        
        findings = []
        temp_dir = tempfile.mkdtemp()
        downloaded = []
        try:
            async with aiohttp.ClientSession() as session:
                for url in urls[:20]:  # limit to 20 JS files
                    try:
                        async with session.get(url, timeout=10) as resp:
                            if resp.status == 200:
                                content = await resp.text()
                                # Save to file
                                filename = url.replace('https://', '').replace('http://', '').replace('/', '_')[:50] + '.js'
                                filepath = os.path.join(temp_dir, filename)
                                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                                    f.write(content)
                                downloaded.append(filepath)
                    except Exception as e:
                        logger.debug("Failed to download JS", url=url, error=str(e))
            
            if downloaded:
                # Run trufflehog on the directory
                cmd = [settings.trufflehog_bin, "filesystem", "--directory", temp_dir, "--json"]
                result = await run_command_safe(cmd, timeout_seconds=180)
                if result.stdout:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            try:
                                data = json.loads(line)
                                findings.append({
                                    "file": data.get("SourceMetadata", {}).get("Data", {}).get("filename", ""),
                                    "secret": data.get("Raw", ""),
                                    "type": data.get("DetectorName", "unknown")
                                })
                            except:
                                pass
        finally:
            # Cleanup temp dir
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
        
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
            logger.info("Saved JS findings", count=len(findings))


async def main():
    worker = JsWorker()
    await worker.run()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())