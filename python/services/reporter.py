"""Report generation service."""
from typing import Optional, Dict, Any, List
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from python.models.target import Target
from python.models.scan import Scan, ScanStatus
from python.models.finding import Finding, Severity, FindingType
from python.database import DatabaseManager


class Reporter:
    """Generate reports from scan results."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
    
    async def get_latest_report(self, domain: str) -> Optional[str]:
        """Generate a formatted report for the latest scan of a domain."""
        async with self.db.session() as session:
            # Get target
            stmt = select(Target).where(Target.domain == domain)
            result = await session.execute(stmt)
            target = result.scalar_one_or_none()
            
            if not target:
                return None
            
            # Get latest scan
            stmt = select(Scan).where(
                Scan.target_id == target.id,
                Scan.status == ScanStatus.COMPLETED
            ).order_by(desc(Scan.completed_at)).limit(1)
            result = await session.execute(stmt)
            scan = result.scalar_one_or_none()
            
            if not scan:
                return f"<b>No completed scans for {domain}</b>"
            
            # Get findings
            stmt = select(Finding).where(Finding.scan_id == scan.id)
            result = await session.execute(stmt)
            findings = result.scalars().all()
            
            # Group findings by type and severity
            subdomains = [f for f in findings if f.finding_type == FindingType.SUBDOMAIN]
            urls = [f for f in findings if f.finding_type == FindingType.URL]
            vulns = [f for f in findings if f.finding_type == FindingType.VULNERABILITY]
            
            # Count by severity
            vuln_by_severity = {s.value: 0 for s in Severity}
            for v in vulns:
                vuln_by_severity[v.severity.value] += 1
            
            # Build report
            lines = [
                f"📄 <b>Recon Report: {domain}</b>",
                f"🕐 Scan completed: {scan.completed_at.strftime('%Y-%m-%d %H:%M:%S')}",
                f"⏱ Duration: {scan.duration_seconds or 0} seconds",
                "",
                "📊 <b>Statistics</b>",
                f"• Subdomains found: {len(subdomains)}",
                f"• URLs discovered: {len(urls)}",
                f"• Vulnerabilities: {len(vulns)}",
            ]
            
            if vulns:
                lines.extend([
                    "",
                    "⚠️ <b>Vulnerabilities by Severity</b>",
                    f"• Critical: {vuln_by_severity['critical']}",
                    f"• High: {vuln_by_severity['high']}",
                    f"• Medium: {vuln_by_severity['medium']}",
                    f"• Low: {vuln_by_severity['low']}",
                    f"• Info: {vuln_by_severity['info']}",
                ])
                
                # Show top critical/high findings
                critical_high = [v for v in vulns if v.severity in (Severity.CRITICAL, Severity.HIGH)]
                if critical_high:
                    lines.append("")
                    lines.append("🔥 <b>Critical/High Findings (first 5)</b>")
                    for v in critical_high[:5]:
                        url = v.finding_data.get('url', 'N/A')
                        template = v.finding_data.get('template_id', 'unknown')
                        lines.append(f"• {template}: {url[:80]}")
            
            return "\n".join(lines)