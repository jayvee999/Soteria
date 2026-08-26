import subprocess, shutil, time, threading, logging
from dataclasses import dataclass
from typing import Dict, List, Optional
from . import database as db
from .kill_switch import register_proc, deregister_proc, register_container

log = logging.getLogger(__name__)

_TOOL_IMAGES: Dict[str, str] = {
    "subfinder": "projectdiscovery/subfinder:latest",
    "assetfinder": "tomnomnom/assetfinder:latest",
    "amass": "caffix/amass:latest",
    "httpx": "projectdiscovery/httpx:latest",
    "nuclei": "projectdiscovery/nuclei:latest",
    "ffuf": "ghcr.io/ffuf/ffuf:latest",
}

_DEFAULT_TIMEOUT = 300
_docker_available = None
_docker_lock = threading.Lock()


@dataclass
class RunResult:
    tool: str
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed: float
    timed_out: bool = False
    docker_used: bool = False
    error: Optional[str] = None


def _check_docker():
    global _docker_available
    with _docker_lock:
        if _docker_available is None:
            try:
                r = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
                _docker_available = r.returncode == 0
            except Exception:
                _docker_available = False
        return _docker_available


def run(tool: str, args: List[str], timeout: int = _DEFAULT_TIMEOUT,
        operator: Optional[str] = None, input_data: Optional[str] = None) -> RunResult:
    docker_used = False
    command = []

    if _check_docker() and tool in _TOOL_IMAGES:
        image = _TOOL_IMAGES[tool]
        cname = f"keres-{tool}-{int(time.time())}"
        command = ["docker", "run", "--rm", "--name", cname, "--network=host",
                   "--read-only", "--tmpfs", "/tmp", image] + args
        register_container(cname)
        docker_used = True

    if not docker_used:
        host_bin = shutil.which(tool)
        if host_bin is None:
            return RunResult(tool, [tool] + args, -1, "", f"{tool} not found", 0, error=f"{tool} not found")
        command = [host_bin] + args

    start = time.monotonic()
    proc = None
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                stdin=subprocess.PIPE if input_data else None, text=True)
        register_proc(proc)
        try:
            stdout, stderr = proc.communicate(input=input_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return RunResult(tool, command, -1, stdout, stderr, time.monotonic() - start,
                             timed_out=True, docker_used=docker_used)
        finally:
            deregister_proc(proc)

        elapsed = time.monotonic() - start
        db.log_action("tool_run", tool=tool, command=" ".join(command),
                      status="ok" if proc.returncode == 0 else "nonzero", operator=operator)
        return RunResult(tool, command, proc.returncode, stdout, stderr, elapsed, docker_used=docker_used)
    except Exception as e:
        if proc:
            try:
                proc.kill()
            except Exception:
                pass
            deregister_proc(proc)
        return RunResult(tool, command, -1, "", str(e), time.monotonic() - start, error=str(e))


def run_subfinder(domain):
    return run("subfinder", ["-d", domain, "-silent"])


def run_assetfinder(domain):
    return run("assetfinder", ["--subs-only", domain])


def run_amass(domain):
    return run("amass", ["enum", "-passive", "-d", domain], timeout=600)


def run_httpx(hosts):
    return run("httpx", ["-silent", "-status-code", "-title", "-tech-detect", "-json"],
               input_data="\n".join(hosts))


def run_nuclei(target, templates=None, severity=None):
    args = ["-u", target, "-silent", "-json"]
    if templates:
        for t in templates:
            args += ["-t", t]
    if severity:
        args += ["-severity", severity]
    return run("nuclei", args, timeout=600)


def run_ffuf(url, wordlist):
    return run("ffuf", ["-u", url, "-w", wordlist, "-s"])
