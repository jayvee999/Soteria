"""
Soteria — Compliance Tagger.

Tags findings with framework controls and stores them.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from .frameworks import get_controls, FRAMEWORK_NAMES

log = logging.getLogger(__name__)


class ComplianceTagger:
    def __init__(self, db=None):
        self.db = db

    def tag_finding(self, finding_id: str, finding_type: str) -> dict:
        """Tag a single finding with compliance controls."""
        controls = get_controls(finding_type)

        if self.db:
            try:
                self.db.execute(
                    """INSERT OR REPLACE INTO compliance_tags
                       (finding_id, finding_type, soc2, iso27001, pcidss,
                        hipaa, gdpr, description, tagged_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        controls["type"],
                        json.dumps(controls["frameworks"].get("SOC2", [])),
                        json.dumps(controls["frameworks"].get("ISO27001", [])),
                        json.dumps(controls["frameworks"].get("PCIDSS", [])),
                        json.dumps(controls["frameworks"].get("HIPAA", [])),
                        json.dumps(controls["frameworks"].get("GDPR", [])),
                        controls["description"],
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                self.db.commit()
            except Exception as e:
                log.warning("Failed to save compliance tag: %s", e)

        return controls

    def get_tag(self, finding_id: str) -> Optional[dict]:
        """Fetch tag for a finding."""
        if not self.db:
            return None
        try:
            row = self.db.execute(
                "SELECT * FROM compliance_tags WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if not row:
                return None
            return {
                "finding_id": row["finding_id"],
                "finding_type": row["finding_type"],
                "frameworks": {
                    "SOC2": json.loads(row["soc2"] or "[]"),
                    "ISO27001": json.loads(row["iso27001"] or "[]"),
                    "PCIDSS": json.loads(row["pcidss"] or "[]"),
                    "HIPAA": json.loads(row["hipaa"] or "[]"),
                    "GDPR": json.loads(row["gdpr"] or "[]"),
                },
                "description": row["description"],
            }
        except Exception:
            return None

    def list_by_framework(self, framework: str) -> list:
        """List all findings tagged with a given framework."""
        if not self.db:
            return []
        col = {
            "SOC2": "soc2",
            "ISO27001": "iso27001",
            "PCIDSS": "pcidss",
            "HIPAA": "hipaa",
            "GDPR": "gdpr",
        }.get(framework.upper())

        if not col:
            return []

        try:
            rows = self.db.execute(
                f"SELECT * FROM compliance_tags WHERE {col} != '[]'"
            ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def framework_summary(self) -> dict:
        """Count findings per framework."""
        if not self.db:
            return {}
        summary = {}
        for fw in ["SOC2", "ISO27001", "PCIDSS", "HIPAA", "GDPR"]:
            summary[fw] = len(self.list_by_framework(fw))
        return summary


def tag_finding(db, finding_id: str, finding_type: str) -> dict:
    """Convenience function."""
    tagger = ComplianceTagger(db=db)
    return tagger.tag_finding(finding_id, finding_type)
