"""Soteria — Report generator (markdown + executive)."""
import logging
from datetime import datetime
from pathlib import Path
from ... import database as db

log = logging.getLogger(__name__)


class ReportGenerator:
    def run(self, program_name: str = "default", format: str = "executive"):
        if format == "executive":
            return self._generate_executive(program_name)
        return self._generate_markdown(program_name)

    def _generate_executive(self, org_id: str):
        from .executive import generate_report
        path = generate_report(db, org_id=org_id, days=30, org_name=org_id)
        print(f"[+] Executive report saved: {path}")
        print(f"    Open in browser: file://{path}")
        return path

    def _generate_markdown(self, program_name: str = ""):
        findings = db.finding_list(verified_only=False, exclude_fp=True)
        if not findings:
            print("[+] No findings to report")
            return None

        out_dir = Path.home() / ".soteria" / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"{program_name}_{datetime.now():%Y%m%d_%H%M%S}.md"

        lines = [
            "# Soteria Report",
            f"**Program:** {program_name}",
            f"**Date:** {datetime.now():%Y-%m-%d}",
            f"**Findings:** {len(findings)}",
            "---",
        ]
        for i, f in enumerate(findings, 1):
            lines.append(f"\n## {i}. {f.title}\n")
            lines.append(f"**Severity:** {f.severity.value} | **Type:** {f.type}")
            lines.append(f"\n**Endpoint:** `{f.url}`")
            lines.append(f"\n{f.description}")
            if f.curl_command:
                lines.append(f"\n```bash\n{f.curl_command}\n```")
            lines.append("\n---")

        path.write_text("\n".join(lines))
        print(f"[+] Markdown report: {path}")
        return path
