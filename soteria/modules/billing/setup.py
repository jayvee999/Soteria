"""
Soteria — Billing schema.
"""
import logging

log = logging.getLogger(__name__)

BILLING_SCHEMA = """
CREATE TABLE IF NOT EXISTS invoices (
    invoice_id      TEXT PRIMARY KEY,
    customer_id     TEXT NOT NULL,
    plan_id         TEXT NOT NULL,
    amount_usd      REAL NOT NULL,
    status          TEXT DEFAULT 'pending',
    description     TEXT,
    payment_link    TEXT,
    payment_ref     TEXT,
    issued_at       TEXT NOT NULL,
    due_at          TEXT,
    paid_at         TEXT,
    cancelled_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_invoice_customer
    ON invoices(customer_id);
CREATE INDEX IF NOT EXISTS idx_invoice_status
    ON invoices(status);
"""


def install(db) -> None:
    try:
        db.executescript(BILLING_SCHEMA)
        log.info("Billing schema installed")
    except Exception as e:
        log.error("Failed to install billing schema: %s", e)
        raise
