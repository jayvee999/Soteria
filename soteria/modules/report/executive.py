"""
Soteria — Executive Report Generator.

Pulls findings, computes metrics, renders an HTML report
that CISOs can show to their board.
"""
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


class ExecutiveReport:
    """Builds the executive summary data."""

    def __init__(self, db=None):
        self.db = db

    def _fetch_findings(self, org_id: str = None, days: int = 30) -> list:
        """Fetch findings from the last N days."""
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        con = self.db._connect() if hasattr(self.db, "_connect") else self.db
        rows = con.execute(
            """SELECT finding_id, severity, title, url, type, description,
                      curl_command, verified, discovered_at
               FROM findings
               WHERE discovered_at >= ?
               ORDER BY
                 CASE severity
                   WHEN 'Critical' THEN 1
                   WHEN 'High' THEN 2
                   WHEN 'Medium' THEN 3
                   WHEN 'Low' THEN 4
                   ELSE 5
                 END,
                 discovered_at DESC""",
            (since,),
        ).fetchall()
        return [dict(r) for r in rows]

    def _count_by_severity(self, findings: list) -> dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            if sev in counts:
                counts[sev] += 1
        return counts

    def _calc_mttr(self, findings: list) -> Optional[float]:
        """Placeholder — real MTTR needs fix-tracking. Returns None for now."""
        return None

    def _top_risks(self, findings: list, limit: int = 5) -> list:
        """Top N findings by severity."""
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_f = sorted(findings, key=lambda f: order.get(f.get("severity"), 5))
        return sorted_f[:limit]

    def _recommendations(self, findings: list) -> list:
        """Simple AI-free recommendations based on severity counts."""
        counts = self._count_by_severity(findings)
        recs = []
        if counts["Critical"] > 0:
            recs.append(
                f"Address {counts['Critical']} critical finding(s) immediately. "
                "These represent immediate risk to production or customer data."
            )
        if counts["High"] > 0:
            recs.append(
                f"Prioritize the {counts['High']} high-severity finding(s) in your "
                "next sprint. Engage engineering leads directly."
            )
        if counts["Medium"] > 0:
            recs.append(
                f"Review the {counts['Medium']} medium-severity finding(s) during "
                "regular backlog grooming."
            )
        if not recs:
            recs.append(
                "No actionable findings in this period. Continue continuous monitoring."
            )
        recs.append(
            "Run Soteria scans continuously. Manual pentests should supplement, "
            "not replace, continuous coverage."
        )
        return recs

    def build(self, org_id: str = "default", days: int = 30, org_name: str = "") -> dict:
        findings = self._fetch_findings(org_id, days)
        counts = self._count_by_severity(findings)

        return {
            "org_name": org_name or org_id,
            "org_id": org_id,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "period_days": days,
            "period_start": (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d"),
            "period_end": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "total_findings": len(findings),
            "counts": counts,
            "mttr": self._calc_mttr(findings),
            "top_risks": self._top_risks(findings),
            "recommendations": self._recommendations(findings),
            "findings": findings,
        }


def generate_report(db, org_id: str = "default", days: int = 30,
                    org_name: str = "", output_path: Path = None) -> Path:
    """Generate an HTML report and return its path."""
    from .html import render_html

    report = ExecutiveReport(db=db).build(org_id, days, org_name)
    html = render_html(report)

    if output_path is None:
        out_dir = Path.home() / ".soteria" / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = out_dir / f"{org_id}_executive_{date_str}.html"

    output_path.write_text(html)
    return output_path
