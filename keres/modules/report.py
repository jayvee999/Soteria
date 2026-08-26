import json
from datetime import datetime
from pathlib import Path
from .. import database as db


class ReportGenerator:
    def run(self, program_name: str, format: str = "markdown"):
        findings = db.finding_list(verified_only=True)
        if not findings:
            print("[+] No verified findings to report")
            return

        if format == "markdown":
            output = self.generate_markdown(findings, program_name)
            path = Path(f"~/keres_output/{program_name}_{datetime.now():%Y%m%d}.md").expanduser()
        elif format == "json":
            output = self.export_json(findings)
            path = Path(f"~/keres_output/{program_name}_{datetime.now():%Y%m%d}.json").expanduser()
        else:
            output = self.generate_markdown(findings, program_name)
            path = Path(f"~/keres_output/{program_name}_{datetime.now():%Y%m%d}.md").expanduser()

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output)
        print(f"[+] Report saved: {path}")

    def generate_markdown(self, findings: list, program_name: str = "") -> str:
        lines = [
            f"# Keres Vulnerability Report",
            f"**Program:** {program_name or 'N/A'}",
            f"**Date:** {datetime.now():%Y-%m-%d}",
            f"**Findings:** {len(findings)}\n---"
        ]
        for i, f in enumerate(findings, 1):
            lines.append(f"\n## {i}. {f.title}\n")
            lines.append(f"**Severity:** {f.severity.value} | **CVSS:** {f.cvss_score or 'N/A'}")
            lines.append(f"\n**Endpoint:** `{f.url}`")
            lines.append(f"\n### Description\n{f.description}")
            if f.curl_command:
                lines.append(f"\n### Reproduction\n```bash\n{f.curl_command}\n```")
            if f.remediation:
                lines.append(f"\n### Remediation\n{f.remediation}")
            lines.append("\n---")
        return "\n".join(lines)

    def export_json(self, findings: list) -> str:
        return json.dumps([f.dict() for f in findings], indent=2, default=str)
