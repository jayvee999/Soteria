"""
Soteria — Compliance schema.
"""
import logging

log = logging.getLogger(__name__)

COMPLIANCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS compliance_tags (
    finding_id      TEXT PRIMARY KEY,
    finding_type    TEXT NOT NULL,
    soc2            TEXT DEFAULT '[]',
    iso27001        TEXT DEFAULT '[]',
    pcidss          TEXT DEFAULT '[]',
    hipaa           TEXT DEFAULT '[]',
    gdpr            TEXT DEFAULT '[]',
    description     TEXT,
    tagged_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_compliance_type
    ON compliance_tags(finding_type);
"""


def install(db) -> None:
    try:
        db.executescript(COMPLIANCE_SCHEMA)
        log.info("Compliance schema installed")
    except Exception as e:
        log.error("Failed to install compliance schema: %s", e)
        raise
