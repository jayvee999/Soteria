"""
Soteria — Authorization schema setup.
"""
import logging

log = logging.getLogger(__name__)

AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS authorizations (
    auth_id             TEXT PRIMARY KEY,
    org_id              TEXT NOT NULL,
    target_domain       TEXT NOT NULL,
    scope_document      TEXT,
    proof_token         TEXT NOT NULL,
    proof_verified      INTEGER DEFAULT 0,
    verification_method TEXT,
    verified_at         TEXT,
    valid_from          TEXT,
    valid_until         TEXT,
    revoked             INTEGER DEFAULT 0,
    revoked_at          TEXT,
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authorization_attempts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id    TEXT NOT NULL,
    domain    TEXT NOT NULL,
    method    TEXT NOT NULL,
    success   INTEGER NOT NULL,
    token     TEXT,
    timestamp TEXT NOT NULL,
    note      TEXT
);

CREATE TABLE IF NOT EXISTS hunts (
    hunt_id         TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    target_domains  TEXT NOT NULL,
    scope_document  TEXT,
    authorized_by   TEXT NOT NULL,
    valid_until     TEXT,
    note            TEXT,
    created_at      TEXT NOT NULL,
    revoked_at      TEXT,
    active          INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_auth_org_domain
    ON authorizations(org_id, target_domain);
CREATE INDEX IF NOT EXISTS idx_auth_verified
    ON authorizations(proof_verified, revoked);
CREATE INDEX IF NOT EXISTS idx_hunt_active
    ON hunts(active, valid_until);
"""


def install(db) -> None:
    try:
        db.executescript(AUTH_SCHEMA)
        log.info("Authorization schema installed")
    except Exception as e:
        log.error("Failed to install authorization schema: %s", e)
        raise
