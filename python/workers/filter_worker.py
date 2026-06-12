"""Filter worker - URL cleaning, classification, scoring, and routing."""
import asyncio
import tempfile
from pathlib import Path
from typing import List, Dict, Set, Optional

from python.workers.base import BaseWorker
from python.redis_client import redis_client
from python.services.url_classifier import URLClassifier
from python.services.scoring import ScoreCalculator
from python.utils.process import run_command_safe
from python.utils.logging_config import get_logger
from python.settings import load_settings

settings = load_settings()
logger = get_logger(__name__)


class FilterWorker(BaseWorker):
    """Process raw URLs: deduplicate, classify, score, and route to specialized queues."""
    
    def __init__(self):
        super().__init__("queue:raw_urls", "filter_worker")
        self.classifier = URLClassifier()
        self.scorer = ScoreCalculator()
    
    async def process_job(self, job_data: dict) -> None:
        """Process a batch of raw URLs and subdomains."""
        scan_id = job_data.get("scan_id")
        domain = job_data.get("domain")
        raw_urls = job_data.get("urls", [])
        subdomains = job_data.get("subdomains", [])
        mode = job_data.get("mode", "safe")
        
        if not raw_urls and not subdomains:
            logger.debug("No data to filter", domain=domain)
            return
        
        logger.info("Filtering URLs", domain=domain, url_count=len(raw_urls), subdomain_count=len(subdomains))
        
        # Step 1: Deduplicate and clean URLs using uro
        cleaned_urls = await self._run_uro(raw_urls)
        
        # Step 2: Extract parameters and paths using unfurl
        params, paths = await self._run_unfurl(cleaned_urls)
        
        # Step 3: Classify URLs
        classified = self.classifier.classify_urls(cleaned_urls, params, paths)
        
        # Step 4: Calculate scores for each URL
        scored_urls = self.scorer.score_urls(classified, raw_urls=raw_urls)
        
        # Step 5: Route to appropriate queues based on classification and score
        await self._route_by_classification(scored_urls, subdomains, scan_id, domain, mode)
        
        logger.info("Filtering complete", domain=domain)
    
    async def _run_uro(self, urls: List[str]) -> List[str]:
        """Run uro to deduplicate and normalize URLs."""
        if not urls:
            return []
        
        input_text = "\n".join(urls)
        cmd = [settings.uro_bin]  # e.g., "uro"
        result = await run_command_safe(cmd, input_data=input_text, timeout_seconds=60)
        if result.returncode == 0 and result.stdout:
            return [line.strip() for line in result.stdout.split('\n') if line.strip()]
        logger.warning("uro failed, using original URLs", error=result.stderr)
        return urls
    
    async def _run_unfurl(self, urls: List[str]) -> tuple[List[str], List[str]]:
        """Extract unique parameters and paths using unfurl."""
        if not urls:
            return [], []
        input_text = "\n".join(urls)
        # Get parameters (keys)
        cmd_keys = [settings.unfurl_bin, "keys"]
        result_keys = await run_command_safe(cmd_keys, input_data=input_text, timeout_seconds=30)
        params = [line.strip() for line in result_keys.stdout.split('\n') if line.strip()] if result_keys.returncode == 0 else []
        
        # Get paths
        cmd_paths = [settings.unfurl_bin, "paths"]
        result_paths = await run_command_safe(cmd_paths, input_data=input_text, timeout_seconds=30)
        paths = [line.strip() for line in result_paths.stdout.split('\n') if line.strip()] if result_paths.returncode == 0 else []
        
        return list(set(params)), list(set(paths))
    
    async def _route_by_classification(self, scored_urls: List[Dict], subdomains: List[str], scan_id: int, domain: str, mode: str) -> None:
        """Push classified URLs to appropriate queues."""
        # Prepare queues
        xss_candidates = []
        ssrf_candidates = []
        redirect_candidates = []
        api_endpoints = []
        js_urls = []
        nuclei_urls = []
        
        for item in scored_urls:
            url = item["url"]
            categories = item.get("categories", [])
            score = item.get("score", 0)
            
            # XSS candidates: URLs with parameters and high XSS score
            if "xss" in categories and score >= 30:
                xss_candidates.append(url)
            
            # SSRF candidates: URLs with parameters like url=, dest=, etc.
            if "ssrf" in categories:
                ssrf_candidates.append(url)
            
            # Open redirect candidates
            if "redirect" in categories:
                redirect_candidates.append(url)
            
            # API endpoints
            if "api" in categories:
                api_endpoints.append(url)
            
            # JavaScript files
            if url.endswith('.js') or '/js/' in url or categories == ["js"]:
                js_urls.append(url)
            
            # For nuclei: only URLs with score >= 20 or API endpoints (except low static)
            if score >= 20 or "api" in categories:
                nuclei_urls.append(url)
        
        # Enqueue XSS candidates (batch)
        if xss_candidates:
            batch_size = 500
            for i in range(0, len(xss_candidates), batch_size):
                batch = xss_candidates[i:i+batch_size]
                await redis_client.enqueue("queue:xss_candidates", {
                    "scan_id": scan_id,
                    "domain": domain,
                    "urls": batch,
                    "mode": mode
                })
            logger.info("Enqueued XSS candidates", count=len(xss_candidates))
        
        # Enqueue takeover candidates (subdomains) - separate queue
        if subdomains:
            await redis_client.enqueue("queue:takeover", {
                "scan_id": scan_id,
                "domain": domain,
                "subdomains": subdomains[:2000],  # limit
                "mode": mode
            })
            logger.info("Enqueued takeover candidates", count=len(subdomains[:2000]))
        
        # Enqueue JS endpoints
        if js_urls:
            await redis_client.enqueue("queue:js_endpoints", {
                "scan_id": scan_id,
                "domain": domain,
                "urls": js_urls[:1000],
                "mode": mode
            })
            logger.info("Enqueued JS endpoints", count=len(js_urls[:1000]))
        
        # Enqueue filtered URLs for nuclei (optional, backup)
        if nuclei_urls and mode == "aggressive":
            await redis_client.enqueue("queue:nuclei", {
                "scan_id": scan_id,
                "domain": domain,
                "urls": nuclei_urls[:2000],
                "mode": mode
            })
            logger.info("Enqueued nuclei candidates", count=len(nuclei_urls[:2000]))
        
        # Notify high-score findings immediately (score >= 70)
        high_score_items = [item for item in scored_urls if item.get("score", 0) >= 70]
        if high_score_items:
            await redis_client.enqueue("queue:notify", {
                "type": "high_priority_urls",
                "domain": domain,
                "urls": high_score_items[:10],
                "scan_id": scan_id
            })


async def main():
    worker = FilterWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())