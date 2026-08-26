import hashlib, hmac, logging, os, platform, secrets, socket, string, bcrypt
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple
from . import database as db
from .models import *
log = logging.getLogger(__name__)
_SESSION_HOURS = 8
_LOCKOUT_MINUTES = 15
_MAX_FAILURES = 3
_PASSWORD_MIN_LEN = 12
_PASSWORD_DAYS = 90
_BCRYPT_ROUNDS = 12
_LICENSE_PREFIX = "BCTL"
_LICENSE_HMAC_SECRET = b"change-me-in-production-32bytes!"

def machine_fingerprint():
    parts = [socket.gethostname(), platform.system(), platform.machine(), platform.processor() or "unknown"]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]

def hash_password(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)).decode()
def verify_password(pw, h): return bcrypt.checkpw(pw.encode(), h.encode())

def validate_password_policy(pw):
    if len(pw) < _PASSWORD_MIN_LEN: return False, "min 12 chars"
    if not (any(c.isupper() for c in pw) and any(c.islower() for c in pw) and any(c.isdigit() for c in pw) and any(c in string.punctuation for c in pw)):
        return False, "need upper, lower, digit, symbol"
    return True, ""

def generate_license_key(role=Role.HUNTER, expires_days=365, note=None):
    lid = secrets.token_hex(6).upper()
    exp = datetime.now(timezone.utc) + timedelta(days=expires_days) if expires_days else None
    exp_iso = exp.isoformat() if exp else "never"
    tag = hmac.new(_LICENSE_HMAC_SECRET, f"{lid}:{role.value}:{exp_iso}".encode(), hashlib.sha256).hexdigest()[:16].upper()
    combined = (lid + tag)[:16]
    groups = [combined[i:i+4] for i in range(0,16,4)]
    plain_key = f"{_LICENSE_PREFIX}-{'-'.join(groups)}"
    key_hash = hashlib.sha256(plain_key.encode()).hexdigest()
    rec = LicenseRecord(license_id=lid, key_hash=key_hash, role=role, expires_at=exp, note=note)
    db.license_create(rec)
    return plain_key, rec

def activate_license(plain_key):
    if not plain_key.startswith(_LICENSE_PREFIX+"-"): return False, "bad format", None
    kh = hashlib.sha256(plain_key.encode()).hexdigest()
    rec = db.license_get_by_key_hash(kh)
    if not rec: return False, "not found", None
    if rec.revoked: return False, "revoked", None
    if rec.expires_at and datetime.now(timezone.utc) > rec.expires_at: return False, "expired", None
    act = LicenseActivation(license_id=rec.license_id, machine_fingerprint=machine_fingerprint())
    db.license_activate(act)
    return True, "activated", rec

def create_user(username, password, role=Role.HUNTER):
    ok, msg = validate_password_policy(password)
    if not ok: return False, msg, None
    if db.user_get(username): return False, "exists", None
    user = User(username=username, password_hash=hash_password(password), role=role)
    db.user_create(user)
    return True, "created", user

def login(username, password):
    user = db.user_get(username)
    if not user: return False, "invalid", None
    if not user.active: return False, "disabled", None
    if not verify_password(password, user.password_hash):
        db.login_attempt_record(LoginAttempt(username=username, success=False))
        return False, "invalid", None
    db.login_attempt_record(LoginAttempt(username=username, success=True))
    token = secrets.token_hex(32)
    now = datetime.now(timezone.utc)
    session = Session(token=token, username=username, role=user.role, created_at=now, expires_at=now+timedelta(hours=_SESSION_HOURS))
    db.session_create(session)
    return True, "ok", session

def validate_session(token):
    s = db.session_get(token)
    if not s or datetime.now(timezone.utc) > s.expires_at: return None
    return s

def save_session_token(token, keres_dir):
    p = keres_dir / ".session"; p.write_text(token); p.chmod(0o600)

def load_session_token(keres_dir):
    p = keres_dir / ".session"
    return p.read_text().strip() if p.exists() else None

def logout(token): db.session_delete(token)
