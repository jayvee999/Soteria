"""
Soteria — Hunt IDs.

A Hunt ID represents a single authorized engagement.
Every scan must reference a valid, active Hunt ID.

This is the legal gate: no Hunt ID, no scan.
"""
import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)


class HuntError(Exception):
    """Raised when a hunt ID is invalid or unauthorized."""


class HuntManager:
    """Manages hunt IDs and authorization checks."""

    def __init__(self, db=None):
        self.db = db

    @staticmethod
    def generate_id(org_id: str, name: str = "") -> str:
        """Generate a unique hunt ID."""
        raw = f"{org_id}:{name}:{secrets.token_hex(8)}"
        digest = hashlib.sha256(raw.encode()).hexdigest()[:12].upper()
        return f"HUNT-{digest}"

    def create_hunt(
        self,
        hunt_id: str,
        org_id: str,
        target_domains: list,
        scope_document: str,
        authorized_by: str,
        valid_until: str = None,
        note: str = "",
    ) -> bool:
        """Create a new hunt with authorized targets."""
        if not self.db:
            return False
        try:
            self.db.execute(
                """INSERT INTO hunts
                   (hunt_id, org_id, target_domains, scope_document,
                    authorized_by, valid_until, note, created_at, active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                (
                    hunt_id,
                    org_id,
                    ",".join(target_domains),
                    scope_document,
                    authorized_by,
                    valid_until,
                    note,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            return True
        except Exception as e:
            log.error("Failed to create hunt: %s", e)
            return False

    def is_valid(self, hunt_id: str) -> tuple:
        """
        Check if a hunt ID is valid and active.
        Returns (valid, reason).
        """
        if not self.db:
            return False, "database not available"
        if not hunt_id:
            return False, "no hunt ID provided"

        try:
            row = self.db.execute(
                "SELECT * FROM hunts WHERE hunt_id = ?", (hunt_id,)
            ).fetchone()

            if not row:
                return False, f"hunt ID not found: {hunt_id}"

            if not row["active"]:
                return False, f"hunt ID is deactivated: {hunt_id}"

            if row["valid_until"]:
                valid_until = datetime.fromisoformat(row["valid_until"])
                if datetime.now(timezone.utc) > valid_until:
                    return False, f"hunt ID expired: {hunt_id}"

            return True, "ok"
        except Exception as e:
            return False, f"hunt validation error: {e}"

    def target_in_scope(self, hunt_id: str, url: str) -> tuple:
        """
        Check if the target URL is in scope for the hunt.
        Returns (in_scope, reason).
        """
        from urllib.parse import urlparse

        if not self.db:
            return False, "database not available"

        try:
            row = self.db.execute(
                "SELECT target_domains FROM hunts WHERE hunt_id = ?",
                (hunt_id,),
            ).fetchone()

            if not row:
                return False, f"hunt ID not found: {hunt_id}"

            domains = [d.strip().lower() for d in row["target_domains"].split(",") if d.strip()]
            parsed = urlparse(url if "://" in url else f"https://{url}")
            host = (parsed.hostname or "").lower()

            for pattern in domains:
                if pattern.startswith("*."):
                    suffix = pattern[2:]
                    if host == suffix or host.endswith("." + suffix):
                        return True, "in scope"
                elif host == pattern or host.endswith("." + pattern):
                    return True, "in scope"

            return False, f"{host} not in scope for hunt {hunt_id}"
        except Exception as e:
            return False, f"scope check error: {e}"

    def require_hunt(self, hunt_id: str, url: str) -> None:
        """
        Raise HuntError if hunt is invalid or target out of scope.
        Call this before any scan.
        """
        valid, reason = self.is_valid(hunt_id)
        if not valid:
            raise HuntError(reason)

        in_scope, reason = self.target_in_scope(hunt_id, url)
        if not in_scope:
            raise HuntError(reason)

    def revoke(self, hunt_id: str) -> bool:
        """Revoke a hunt ID. Scans can no longer run."""
        if not self.db:
            return False
        try:
            self.db.execute(
                "UPDATE hunts SET active = 0, revoked_at = ? WHERE hunt_id = ?",
                (datetime.now(timezone.utc).isoformat(), hunt_id),
            )
            return True
        except Exception as e:
            log.error("Failed to revoke hunt: %s", e)
            return False
