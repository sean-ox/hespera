"""JavaScript Worker - extract endpoints and secrets from JS files."""
import asyncio
import ipaddress
import json
import os
import re
import shutil
import socket
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
from urllib.parse import urlparse

import aiohttp

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

# Maximum size for a single downloaded JS file (5 MB)
MAX_JS_SIZE_BYTES = 5 * 1024 * 1024

# Networks that must never be fetched (SSRF prevention)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / AWS metadata
    ipaddress.ip_network("100.64.0.0/10"),    # shared address space
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
]


def _is_safe_url(url: str) -> bool:
    """
    Return True only if the URL is safe to fetch (no SSRF risk).

    Checks:
    1. Scheme must be http or https — blocks file://, ftp://, etc.
    2. Hostname must resolve to a public IP address.
    3. Resolved IP must not belong to any private/link-local network.
    """
    try:
        parsed = urlparse(url)

        # 1. Scheme whitelist
        if parsed.scheme not in ("http", "https"):
            logger.warning("Blocked non-http URL scheme", url=url, scheme=parsed.scheme)
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # 2. Resolve hostname → IP
        try:
            addr_infos = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            logger.warning("Could not resolve hostname", hostname=hostname)
            return False

        # 3. Check every resolved address against blocked networks
        for _family, _type, _proto, _canonname, sockaddr in addr_infos:
            raw_ip = sockaddr[0]
            try:
                ip = ipaddress.ip_address(raw_ip)
            except ValueError:
                continue
            for network in _BLOCKED_NETWORKS:
                if ip in network:
                    logger.warning(
                        "Blocked SSRF attempt — private IP",
                        url=url,
                        resolved_ip=raw_ip,
                        network=str(network),
                    )
                    return False

    except Exception as exc:
        logger.warning("URL safety check error", url=url, error=str(exc))
        return False

    return True


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
        """Download JS files and extract endpoints + secrets."""
        findings = []

        # 1. Use jsluice to extract endpoints from JS URLs
        if settings.jsluice_bin:
            endpoints = await self._run_jsluice(js_urls)
            for endpoint in endpoints:
                finding_data = {
                    "url": endpoint,
                    "source_js": "jsluice",
                    "type": "endpoint",
                }
                dedup_hash = DEDUPLICATOR.compute_hash("js_endpoint", finding_data)
                findings.append({
                    "scan_id": scan_id,
                    "target_id": None,
                    "finding_type": FindingType.URL,
                    "finding_data": finding_data,
                    "severity": Severity.INFO,
                    "is_new": True,
                    "dedup_hash": dedup_hash,
                })

        # 2. Use trufflehog to find secrets
        if settings.trufflehog_bin and js_urls:
            secrets = await self._run_trufflehog(js_urls)
            for secret in secrets:
                finding_data = {
                    "file": secret.get("file", ""),
                    "secret": secret.get("secret", "")[:100],
                    "type": secret.get("type", "unknown"),
                    "tool": "trufflehog",
                }
                dedup_hash = DEDUPLICATOR.compute_hash("secret", finding_data)
                findings.append({
                    "scan_id": scan_id,
                    "target_id": None,
                    "finding_type": FindingType.VULNERABILITY,
                    "finding_data": finding_data,
                    "severity": Severity.CRITICAL,
                    "is_new": True,
                    "dedup_hash": dedup_hash,
                })

        if findings:
            await self._save_findings(findings)
            critical_secrets = [f for f in findings if f.get("severity") == Severity.CRITICAL]
            if critical_secrets:
                await redis_client.enqueue("queue:notify", {
                    "type": "secrets_found",
                    "domain": domain,
                    "secrets": [f["finding_data"] for f in critical_secrets[:3]],
                })

    async def _run_jsluice(self, urls: List[str]) -> List[str]:
        """Run jsluice urls command to extract endpoints."""
        input_text = "\n".join(urls)
        cmd = [settings.jsluice_bin, "urls"]
        result = await run_command_safe(cmd, input_data=input_text, timeout_seconds=120)
        if result.returncode == 0 and result.stdout:
            return [
                line.strip()
                for line in result.stdout.split("\n")
                if line.strip() and line.startswith("http")
            ]
        return []

    async def _run_trufflehog(self, urls: List[str]) -> List[Dict]:
        """
        Download JS files to a temp directory and run trufflehog on them.

        Each URL is validated with _is_safe_url() before any network request
        is made, preventing SSRF to internal/cloud-metadata endpoints.
        Downloads are capped at MAX_JS_SIZE_BYTES to prevent disk exhaustion.
        """
        findings: List[Dict] = []
        temp_dir = tempfile.mkdtemp()

        try:
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            connector = aiohttp.TCPConnector(ssl=True)

            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            ) as session:
                for url in urls[:20]:  # hard cap: 20 JS files per job

                    # SSRF guard — skip any URL that resolves to a private address
                    if not _is_safe_url(url):
                        continue

                    try:
                        async with session.get(
                            url,
                            allow_redirects=False,   # no redirect-based SSRF
                            max_line_size=8190,
                        ) as resp:
                            if resp.status != 200:
                                continue

                            # Size guard — reject oversized responses
                            content_length = resp.content_length
                            if content_length and content_length > MAX_JS_SIZE_BYTES:
                                logger.warning(
                                    "JS file too large, skipping",
                                    url=url,
                                    size=content_length,
                                )
                                continue

                            # Stream read with hard byte cap
                            raw = await resp.content.read(MAX_JS_SIZE_BYTES + 1)
                            if len(raw) > MAX_JS_SIZE_BYTES:
                                logger.warning(
                                    "JS response exceeded size cap, skipping",
                                    url=url,
                                )
                                continue

                            content = raw.decode("utf-8", errors="ignore")

                            # Safe filename: only alphanum + underscore + .js
                            safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", url)[:50] + ".js"
                            filepath = os.path.join(temp_dir, safe_name)
                            with open(filepath, "w", encoding="utf-8", errors="ignore") as fh:
                                fh.write(content)

                    except aiohttp.ClientError as exc:
                        logger.debug("Failed to download JS", url=url, error=str(exc))

            # Run trufflehog on the temp directory
            js_files = list(Path(temp_dir).glob("*.js"))
            if js_files:
                cmd = [
                    settings.trufflehog_bin,
                    "filesystem",
                    "--directory", temp_dir,
                    "--json",
                ]
                result = await run_command_safe(cmd, timeout_seconds=180)
                if result.stdout:
                    for line in result.stdout.split("\n"):
                        if not line.strip():
                            continue
                        try:
                            data = json.loads(line)
                            findings.append({
                                "file": data.get("SourceMetadata", {}).get("Data", {}).get("filename", ""),
                                "secret": data.get("Raw", ""),
                                "type": data.get("DetectorName", "unknown"),
                            })
                        except json.JSONDecodeError:
                            pass

        finally:
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
    asyncio.run(main())