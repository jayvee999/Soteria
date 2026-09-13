"""
Soteria — Customer Manager.

Manages customer records, links to hunts, and dashboards.
"""
import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)


class CustomerError(Exception):
    """Raised on customer operation failures."""


VALID_PLANS = ["pilot", "starter", "standard", "premium", "enterprise"]
VALID_STATUSES = ["active", "paused", "cancelled"]


class CustomerManager:
    """Create, list, show, update, delete customers."""

    def __init__(self, db=None):
        self.db = db

    @staticmethod
    def generate_id(name: str) -> str:
        """Generate a unique customer ID."""
        raw = f"{name}:{secrets.token_hex(6)}"
        digest = hashlib.sha256(raw.encode()).hexdigest()[:10].upper()
        return f"CUST-{digest}"

    def create(
        self,
        name: str,
        contact_email: str = "",
        contact_name: str = "",
        plan: str = "standard",
        notes: str = "",
    ) -> tuple:
        """Create a new customer. Returns (ok, customer_id_or_error)."""
        if not self.db:
            return False, "database not available"
        if not name:
            return False, "name required"
        if plan not in VALID_PLANS:
            return False, f"invalid plan (must be one of {VALID_PLANS})"

        customer_id = self.generate_id(name)
        org_id = customer_id.lower().replace("cust-", "org-")

        now = datetime.now(timezone.utc).isoformat()
        try:
            self.db.execute(
                """INSERT INTO customers
                   (customer_id, org_id, name, contact_email, contact_name,
                    plan, status, notes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (customer_id, org_id, name, contact_email, contact_name,
                 plan, "active", notes, now),
            )
            self.db.commit()
            return True, customer_id
        except Exception as e:
            log.error("Failed to create customer: %s", e)
            return False, str(e)

    def get(self, customer_id: str) -> Optional[dict]:
        """Fetch a customer by ID."""
        if not self.db:
            return None
        try:
            row = self.db.execute(
                "SELECT * FROM customers WHERE customer_id = ? OR org_id = ?",
                (customer_id, customer_id),
            ).fetchone()
            return dict(row) if row else None
        except Exception:
            return None

    def get_by_org(self, org_id: str) -> Optional[dict]:
        """Fetch a customer by org_id."""
        if not self.db:
            return None
        try:
            row = self.db.execute(
                "SELECT * FROM customers WHERE org_id = ?", (org_id,)
            ).fetchone()
            return dict(row) if row else None
        except Exception:
            return None

    def list_all(self, status: str = None) -> list:
        """List customers, optionally filtered by status."""
        if not self.db:
            return []
        try:
            if status:
                rows = self.db.execute(
                    "SELECT * FROM customers WHERE status = ? ORDER BY created_at DESC",
                    (status,),
                ).fetchall()
            else:
                rows = self.db.execute(
                    "SELECT * FROM customers ORDER BY created_at DESC"
                ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def update(
        self,
        customer_id: str,
        plan: str = None,
        status: str = None,
        contact_email: str = None,
        contact_name: str = None,
        notes: str = None,
    ) -> tuple:
        """Update customer fields. Returns (ok, message)."""
        if not self.db:
            return False, "database not available"

        cust = self.get(customer_id)
        if not cust:
            return False, f"customer not found: {customer_id}"

        updates = []
        params = []

        if plan is not None:
            if plan not in VALID_PLANS:
                return False, f"invalid plan"
            updates.append("plan = ?")
            params.append(plan)

        if status is not None:
            if status not in VALID_STATUSES:
                return False, f"invalid status"
            updates.append("status = ?")
            params.append(status)
            if status == "cancelled":
                updates.append("cancelled_at = ?")
                params.append(datetime.now(timezone.utc).isoformat())

        if contact_email is not None:
            updates.append("contact_email = ?")
            params.append(contact_email)

        if contact_name is not None:
            updates.append("contact_name = ?")
            params.append(contact_name)

        if notes is not None:
            updates.append("notes = ?")
            params.append(notes)

        updates.append("updated_at = ?")
        params.append(datetime.now(timezone.utc).isoformat())

        params.append(cust["customer_id"])

        try:
            self.db.execute(
                f"UPDATE customers SET {', '.join(updates)} WHERE customer_id = ?",
                params,
            )
            self.db.commit()
            return True, "updated"
        except Exception as e:
            return False, str(e)

    def delete(self, customer_id: str) -> tuple:
        """Delete a customer (soft delete via status)."""
        return self.update(customer_id, status="cancelled")

    def stats(self, customer_id: str) -> dict:
        """Get stats: hunts, findings, severities."""
        if not self.db:
            return {}
        cust = self.get(customer_id)
        if not cust:
            return {}

        org_id = cust["org_id"]

        try:
            hunts = self.db.execute(
                "SELECT COUNT(*) FROM hunts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
        except Exception:
            hunts = 0

        try:
            findings = self.db.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
            ).fetchall()
            counts = {r["severity"]: r["cnt"] for r in findings}
        except Exception:
            counts = {}

        return {
            "hunts": hunts,
            "findings": counts,
            "total_findings": sum(counts.values()) if counts else 0,
        }

    def link_hunt(self, hunt_id: str, customer_id: str) -> tuple:
        """Link a hunt ID to a customer."""
        if not self.db:
            return False, "database not available"
        cust = self.get(customer_id)
        if not cust:
            return False, f"customer not found"

        try:
            self.db.execute(
                "UPDATE hunts SET org_id = ? WHERE hunt_id = ?",
                (cust["org_id"], hunt_id),
            )
            self.db.commit()
            return True, f"hunt {hunt_id} linked to {customer_id}"
        except Exception as e:
            return False, str(e)
