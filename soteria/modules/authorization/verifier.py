"""
Soteria — Ownership Verification.

Proves the customer owns a target before any scan runs.
Supports DNS TXT and file-based verification.

CFAA / Nigerian Cybercrimes Act protection.
"""
import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger(__name__)


class AuthorizationError(Exception):
    """Raised when a target is not verified as owned by the customer."""


class OwnershipVerifier:
    """Verifies customer ownership of a target domain."""

    DNS_PREFIX = "_soteria-verify"
    FILE_PATH = "/.well-known/soteria-verify.txt"

    def __init__(self, db=None):
        self.db = db

    @staticmethod
    def generate_token(org_id: str, domain: str) -> str:
        raw = f"{org_id}:{domain}:{secrets.token_hex(8)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _record_attempt(self, org_id, domain, method, success, token, note=""):
        if not self.db:
            return
        try:
            self.db.execute(
                """INSERT INTO authorization_attempts
                   (org_id, domain, method, success, token, timestamp, note)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (org_id, domain, method, int(success),
                 token[:8] + "...",
                 datetime.now(timezone.utc).isoformat(), note),
            )
        except Exception as e:
            log.warning("Failed to record auth attempt: %s", e)

    def verify_dns(self, domain: str, token: str, org_id: str = "") -> bool:
        import subprocess
        record_name = f"{self.DNS_PREFIX}.{domain}"
        success = False
        try:
            result = subprocess.run(
                ["dig", "+short", "TXT", record_name],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout.strip().strip('"')
            success = token in output
        except FileNotFoundError:
            try:
                result = subprocess.run(
                    ["nslookup", "-type=TXT", record_name],
                    capture_output=True, text=True, timeout=15,
                )
                success = token in result.stdout
            except Exception as e:
                log.warning("DNS verify failed for %s: %s", domain, e)
        except Exception as e:
            log.warning("DNS verify failed for %s: %s", domain, e)

        self._record_attempt(org_id, domain, "dns", success, token,
                             note=f"lookup: {record_name}")
        return success

    def verify_file(self, url: str, token: str, org_id: str = "") -> bool:
        import httpx
        parsed = urlparse(url if "://" in url else f"https://{url}")
        domain = parsed.hostname or url
        verify_url = f"https://{domain}{self.FILE_PATH}"
        success = False
        try:
            with httpx.Client(timeout=15, verify=False) as client:
                resp = client.get(verify_url)
                success = resp.status_code == 200 and token in resp.text
        except Exception as e:
            log.warning("File verify failed for %s: %s", domain, e)

        self._record_attempt(org_id, domain, "file", success, token,
                             note=f"url: {verify_url}")
        return success

    def verify_target(self, org_id, domain, token, prefer="dns"):
        if prefer == "dns":
            if self.verify_dns(domain, token, org_id):
                return {"verified": True, "method": "dns", "domain": domain}
            if self.verify_file(domain, token, org_id):
                return {"verified": True, "method": "file", "domain": domain}
        else:
            if self.verify_file(domain, token, org_id):
                return {"verified": True, "method": "file", "domain": domain}
            if self.verify_dns(domain, token, org_id):
                return {"verified": True, "method": "dns", "domain": domain}
        return {"verified": False, "method": None, "domain": domain,
                "error": "Token not found in DNS or file"}

    def is_authorized(self, org_id: str, url: str, db=None) -> bool:
        if not db:
            db = self.db
        if not db:
            return False
        parsed = urlparse(url if "://" in url else f"https://{url}")
        domain = parsed.hostname or url
        try:
            row = db.execute(
                """SELECT proof_verified, revoked, valid_until
                   FROM authorizations
                   WHERE org_id = ? AND target_domain = ?
                   ORDER BY created_at DESC LIMIT 1""",
                (org_id, domain),
            ).fetchone()
            if not row:
                return False
            if row["revoked"]:
                return False
            if not row["proof_verified"]:
                return False
            if row["valid_until"]:
                valid_until = datetime.fromisoformat(row["valid_until"])
                if datetime.now(timezone.utc) > valid_until:
                    return False
            return True
        except Exception as e:
            log.warning("Auth check failed for %s: %s", url, e)
            return False
