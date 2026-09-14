"""
Soteria — Billing Manager.
"""
import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from .plans import get_plan

log = logging.getLogger(__name__)


class BillingError(Exception):
    pass


class BillingManager:
    def __init__(self, db=None):
        self.db = db

    @staticmethod
    def generate_invoice_id(customer_id: str) -> str:
        raw = f"{customer_id}:{secrets.token_hex(4)}:{datetime.now().isoformat()}"
        digest = hashlib.sha256(raw.encode()).hexdigest()[:10].upper()
        return f"INV-{digest}"

    def create_invoice(self, customer_id: str, plan_id: str, description: str = "") -> tuple:
        if not self.db:
            return False, "database not available"

        plan = get_plan(plan_id)
        if not plan:
            return False, f"unknown plan: {plan_id}"

        invoice_id = self.generate_invoice_id(customer_id)
        now = datetime.now(timezone.utc)
        due_at = now + timedelta(days=14)

        try:
            self.db.execute(
                """INSERT INTO invoices
                   (invoice_id, customer_id, plan_id, amount_usd, status,
                    description, issued_at, due_at)
                   VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)""",
                (
                    invoice_id,
                    customer_id,
                    plan_id,
                    plan["price_usd"],
                    description or f"{plan['name']} plan",
                    now.isoformat(),
                    due_at.isoformat(),
                ),
            )
            self.db.commit()
            return True, invoice_id
        except Exception as e:
            log.error("Failed to create invoice: %s", e)
            return False, str(e)

    def get_invoice(self, invoice_id: str) -> Optional[dict]:
        if not self.db:
            return None
        try:
            row = self.db.execute(
                "SELECT * FROM invoices WHERE invoice_id = ?", (invoice_id,)
            ).fetchone()
            return dict(row) if row else None
        except Exception:
            return None

    def list_invoices(self, customer_id: str = None, status: str = None) -> list:
        if not self.db:
            return []
        try:
            query = "SELECT * FROM invoices WHERE 1=1"
            params = []
            if customer_id:
                query += " AND customer_id = ?"
                params.append(customer_id)
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY issued_at DESC"
            rows = self.db.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def mark_paid(self, invoice_id: str, payment_ref: str = "") -> tuple:
        if not self.db:
            return False, "database not available"
        inv = self.get_invoice(invoice_id)
        if not inv:
            return False, f"invoice not found: {invoice_id}"
        if inv["status"] == "paid":
            return False, "already paid"
        try:
            self.db.execute(
                """UPDATE invoices
                   SET status = 'paid', paid_at = ?, payment_ref = ?
                   WHERE invoice_id = ?""",
                (datetime.now(timezone.utc).isoformat(), payment_ref, invoice_id),
            )
            self.db.commit()
            return True, "marked paid"
        except Exception as e:
            return False, str(e)

    def revenue_summary(self) -> dict:
        if not self.db:
            return {}
        try:
            all_inv = self.db.execute(
                "SELECT status, amount_usd FROM invoices"
            ).fetchall()
            paid_total = sum(r["amount_usd"] for r in all_inv if r["status"] == "paid")
            pending_total = sum(r["amount_usd"] for r in all_inv if r["status"] == "pending")
            paid_count = sum(1 for r in all_inv if r["status"] == "paid")
            pending_count = sum(1 for r in all_inv if r["status"] == "pending")
            return {
                "paid_total": paid_total,
                "pending_total": pending_total,
                "paid_count": paid_count,
                "pending_count": pending_count,
            }
        except Exception:
            return {}
