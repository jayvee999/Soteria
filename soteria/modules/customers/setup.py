"""
Soteria — Customer schema.
Adds tables for customers, links hunts to customers.
"""
import logging

log = logging.getLogger(__name__)

CUSTOMER_SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    customer_id     TEXT PRIMARY KEY,
    org_id          TEXT UNIQUE NOT NULL,
    name            TEXT NOT NULL,
    contact_email   TEXT,
    contact_name    TEXT,
    plan            TEXT DEFAULT 'standard',
    status          TEXT DEFAULT 'active',
    notes           TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT,
    cancelled_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_customer_status
    ON customers(status);
CREATE INDEX IF NOT EXISTS idx_customer_org
    ON customers(org_id);
"""


def install(db) -> None:
    try:
        db.executescript(CUSTOMER_SCHEMA)
        log.info("Customer schema installed")
    except Exception as e:
        log.error("Failed to install customer schema: %s", e)
        raise
