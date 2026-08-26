import signal, sys, subprocess, threading, time, logging
from pathlib import Path
from typing import Set

log = logging.getLogger(__name__)

_DOUBLE_TAP_WINDOW = 2.0

_procs: Set[subprocess.Popen] = set()
_containers: Set[str] = set()
_procs_lock = threading.Lock()
_containers_lock = threading.Lock()
_last_sigint = None
_keres_dir = None


def init(keres_dir):
    global _keres_dir
    _keres_dir = keres_dir
    signal.signal(signal.SIGINT, _handle_sigint)
    signal.signal(signal.SIGTERM, _handle_sigterm)


def register_proc(proc):
    with _procs_lock:
        _procs.add(proc)


def deregister_proc(proc):
    with _procs_lock:
        _procs.discard(proc)


def register_container(name):
    with _containers_lock:
        _containers.add(name)


def deregister_container(name):
    with _containers_lock:
        _containers.discard(name)


def _handle_sigint(signum, frame):
    global _last_sigint
    now = time.monotonic()
    if _last_sigint is not None and (now - _last_sigint) <= _DOUBLE_TAP_WINDOW:
        _emergency_shutdown("double SIGINT")
    else:
        _last_sigint = now
        print("\n[!] Ctrl+C again within 2s for emergency shutdown", file=sys.stderr)


def _handle_sigterm(signum, frame):
    _emergency_shutdown("SIGTERM")


def _emergency_shutdown(reason):
    print(f"\n[!] KILL SWITCH TRIGGERED ({reason})", file=sys.stderr)

    with _procs_lock:
        procs = list(_procs)
    for proc in procs:
        try:
            proc.kill()
        except Exception:
            pass

    with _containers_lock:
        containers = list(_containers)
    for cname in containers:
        try:
            subprocess.run(["docker", "kill", cname], timeout=5, capture_output=True)
        except Exception:
            pass

    if _keres_dir:
        token_path = _keres_dir / ".session"
        if token_path.exists():
            try:
                token_path.unlink()
            except Exception:
                pass

    try:
        from . import database as db
        db.log_action("kill_switch", status="triggered", output_summary=reason)
    except Exception:
        pass

    print("[!] All jobs terminated. Exiting.", file=sys.stderr)
    sys.exit(1)
