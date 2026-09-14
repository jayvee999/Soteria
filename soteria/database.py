import sqlite3, json, logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List
from contextlib import contextmanager
from .models import *

log = logging.getLogger(__name__)
_DB_PATH = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'hunter',
    created_at TEXT,
    last_login TEXT,
    password_changed_at TEXT,
    locked_until TEXT,
    active INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    success INTEGER,
    timestamp TEXT,
    ip_hint TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    username TEXT,
    role TEXT,
    created_at TEXT,
    expires_at TEXT
);
CREATE TABLE IF NOT EXISTS recon_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_domain TEXT,
    url TEXT,
    status_code INTEGER,
    technologies TEXT DEFAULT '[]',
    title TEXT,
    headers TEXT DEFAULT '{}',
    content_length INTEGER,
    discovered_at TEXT,
    behind_cdn INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    url TEXT,
    type TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    raw_request TEXT,
    raw_response TEXT,
    curl_command TEXT,
    reproduction_steps TEXT DEFAULT '[]',
    cvss_score REAL,
    cvss_vector TEXT,
    remediation TEXT,
    verified INTEGER DEFAULT 0,
    false_positive INTEGER DEFAULT 0,
    reported INTEGER DEFAULT 0,
    discovered_at TEXT,
    ai_notes TEXT
);
CREATE TABLE IF NOT EXISTS scan_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    action TEXT,
    target TEXT,
    tool TEXT,
    command TEXT,
    output_summary TEXT,
    status TEXT DEFAULT 'ok',
    operator TEXT
);
CREATE TABLE IF NOT EXISTS training_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    instruction TEXT,
    input TEXT,
    output TEXT,
    category TEXT,
    source TEXT,
    created_at TEXT
);
"""


def init(db_path: Path):
    global _DB_PATH
    _DB_PATH = db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = _connect()
    con.executescript(_SCHEMA)

    # Install authorization schema
    try:
        from .modules.authorization.setup import AUTH_SCHEMA
        con.executescript(AUTH_SCHEMA)
    except Exception as e:
        log.warning("Authorization schema install failed: %s", e)

    # Install customer schema
    try:
        from .modules.customers.setup import CUSTOMER_SCHEMA
        con.executescript(CUSTOMER_SCHEMA)
    except Exception as e:
        log.warning("Customer schema install failed: %s", e)

    # Install billing schema
    try:
        from .modules.billing.setup import BILLING_SCHEMA
        con.executescript(BILLING_SCHEMA)
    except Exception as e:
        log.warning("Billing schema install failed: %s", e)

    # Install compliance schema
    try:
        from .modules.compliance.setup import COMPLIANCE_SCHEMA
        con.executescript(COMPLIANCE_SCHEMA)
    except Exception as e:
        log.warning("Compliance schema install failed: %s", e)

    con.close()


def _connect():
    if _DB_PATH is None:
        raise RuntimeError("database not initialised")
    con = sqlite3.connect(str(_DB_PATH), isolation_level=None, timeout=10)
    con.row_factory = sqlite3.Row
    return con


@contextmanager
def _tx():
    con = _connect()
    try:
        con.execute("BEGIN")
        yield con
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()


def _iso(dt):
    return dt.isoformat() if dt else None


def _dt(s):
    return datetime.fromisoformat(s) if s else None


def _now():
    return datetime.now(timezone.utc).isoformat()


def log_action(action, **kw):
    try:
        with _tx() as con:
            con.execute(
                "INSERT INTO scan_log (timestamp,action,target,tool,command,output_summary,status,operator) VALUES (?,?,?,?,?,?,?,?)",
                (_now(), action, kw.get('target'), kw.get('tool'), kw.get('command'),
                 kw.get('output_summary'), kw.get('status', 'ok'), kw.get('operator'))
            )
    except Exception:
        pass


def user_create(user):
    with _tx() as con:
        cur = con.execute(
            "INSERT INTO users (username,password_hash,role,created_at,password_changed_at,active) VALUES (?,?,?,?,?,?)",
            (user.username, user.password_hash, user.role.value,
             _iso(user.created_at), _iso(user.password_changed_at), int(user.active))
        )
        user.id = cur.lastrowid
    return user


def user_get(username):
    con = _connect()
    row = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    con.close()
    if not row:
        return None
    return User(
        id=row["id"], username=row["username"], password_hash=row["password_hash"],
        role=Role(row["role"]), created_at=_dt(row["created_at"]),
        last_login=_dt(row["last_login"]), password_changed_at=_dt(row["password_changed_at"]),
        locked_until=_dt(row["locked_until"]), active=bool(row["active"])
    )


def user_list():
    con = _connect()
    rows = con.execute("SELECT * FROM users").fetchall()
    con.close()
    return [
        User(id=r["id"], username=r["username"], password_hash=r["password_hash"],
             role=Role(r["role"]), created_at=_dt(r["created_at"]),
             last_login=_dt(r["last_login"]), password_changed_at=_dt(r["password_changed_at"]),
             locked_until=_dt(r["locked_until"]), active=bool(r["active"]))
        for r in rows
    ]


def login_attempt_record(attempt):
    with _tx() as con:
        con.execute(
            "INSERT INTO login_attempts (username,success,timestamp) VALUES (?,?,?)",
            (attempt.username, int(attempt.success), _iso(attempt.timestamp))
        )


def login_attempt_recent_failures(username, since):
    con = _connect()
    n = con.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE username=? AND success=0 AND timestamp>?",
        (username, _iso(since))
    ).fetchone()[0]
    con.close()
    return n


def session_create(session):
    with _tx() as con:
        con.execute(
            "INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?)",
            (session.token, session.username, session.role.value,
             _iso(session.created_at), _iso(session.expires_at))
        )


def session_get(token):
    con = _connect()
    row = con.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
    con.close()
    if not row:
        return None
    return Session(
        token=row["token"], username=row["username"], role=Role(row["role"]),
        created_at=_dt(row["created_at"]), expires_at=_dt(row["expires_at"])
    )


def session_delete(token):
    with _tx() as con:
        con.execute("DELETE FROM sessions WHERE token=?", (token,))


def finding_save(finding):
    with _tx() as con:
        con.execute(
            "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (finding.finding_id, finding.url, finding.type, finding.severity.value,
             finding.title, finding.description, finding.raw_request, finding.raw_response,
             finding.curl_command, json.dumps(finding.reproduction_steps),
             finding.cvss_score, finding.cvss_vector, finding.remediation,
             int(finding.verified), int(finding.false_positive), int(finding.reported),
             _iso(finding.discovered_at), finding.ai_notes)
        )
    return finding


def finding_list(verified_only=False, exclude_fp=True):
    clauses = []
    if verified_only:
        clauses.append("verified=1")
    if exclude_fp:
        clauses.append("false_positive=0")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    con = _connect()
    rows = con.execute(f"SELECT * FROM findings {where} ORDER BY discovered_at DESC").fetchall()
    con.close()
    return [
        Finding(
            finding_id=r["finding_id"], url=r["url"], type=r["type"],
            severity=Severity(r["severity"]), title=r["title"], description=r["description"],
            raw_request=r["raw_request"], raw_response=r["raw_response"],
            curl_command=r["curl_command"], reproduction_steps=json.loads(r["reproduction_steps"]),
            cvss_score=r["cvss_score"], cvss_vector=r["cvss_vector"],
            remediation=r["remediation"], verified=bool(r["verified"]),
            false_positive=bool(r["false_positive"]), reported=bool(r["reported"]),
            discovered_at=_dt(r["discovered_at"]), ai_notes=r["ai_notes"]
        )
        for r in rows
    ]


def finding_update_verification(fid, verified, fp):
    with _tx() as con:
        con.execute(
            "UPDATE findings SET verified=?, false_positive=? WHERE finding_id=?",
            (int(verified), int(fp), fid)
        )


def recon_save(result):
    with _tx() as con:
        cur = con.execute(
            "INSERT INTO recon_results (target_domain,url,status_code,technologies,title,headers,content_length,discovered_at,behind_cdn) VALUES (?,?,?,?,?,?,?,?,?)",
            (result.target_domain, result.url, result.status_code,
             json.dumps(result.technologies), result.title, json.dumps(result.headers),
             result.content_length, _iso(result.discovered_at), int(result.behind_cdn))
        )
        result.id = cur.lastrowid
    return result


def training_save(entry):
    with _tx() as con:
        cur = con.execute(
            "INSERT INTO training_data (instruction,input,output,category,source,created_at) VALUES (?,?,?,?,?,?)",
            (entry.instruction, entry.input, entry.output, entry.category,
             entry.source, _iso(entry.created_at))
        )
        entry.id = cur.lastrowid
    return entry


def training_count():
    con = _connect()
    n = con.execute("SELECT COUNT(*) FROM training_data").fetchone()[0]
    con.close()
    return n


def training_list(category=None):
    con = _connect()
    if category:
        rows = con.execute("SELECT * FROM training_data WHERE category=? ORDER BY created_at DESC", (category,)).fetchall()
    else:
        rows = con.execute("SELECT * FROM training_data ORDER BY created_at DESC").fetchall()
    con.close()
    return [
        TrainingEntry(id=r["id"], instruction=r["instruction"], input=r["input"],
                      output=r["output"], category=r["category"], source=r["source"],
                      created_at=_dt(r["created_at"]))
        for r in rows
    ]
