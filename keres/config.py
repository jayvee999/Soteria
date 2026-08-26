import logging, re, yaml
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger(__name__)

_DEFAULT = {
    "defaults": {
        "rate_limit": 10,
        "max_threads": 10,
        "timeout": 15,
        "ai_backend": "deepseek",
        "output_dir": "~/.keres/output"
    },
    "programs": {}
}

MAX_RATE = 50

class ScopeError(Exception):
    pass

class Config:
    def __init__(self, data):
        self._data = data

    @property
    def defaults(self):
        return self._data.get("defaults", {})

    @property
    def rate_limit(self):
        return min(float(self.defaults.get("rate_limit", 10)), MAX_RATE)

    @property
    def max_threads(self):
        return min(int(self.defaults.get("max_threads", 10)), 20)

    @property
    def timeout(self):
        return int(self.defaults.get("timeout", 15))

    @property
    def user_agents(self):
        return self.defaults.get("user_agents", ["Mozilla/5.0"])

    @property
    def ai_backend(self):
        return self.defaults.get("ai_backend", "deepseek")

    @property
    def output_dir(self):
        return Path(self.defaults.get("output_dir", "~/.keres/output")).expanduser()

    def program(self, name):
        return self._data.get("programs", {}).get(name, {})

    def get(self, k, d=None):
        return self._data.get(k, d)

    def _scope(self, prog):
        return self._data.get("programs", {}).get(prog, {})

    def _match_domain(self, target, pattern):
        if pattern.startswith("*."):
            return target == pattern[2:] or target.endswith("." + pattern[2:])
        return target == pattern or target.endswith("." + pattern)

    def _host(self, url):
        return urlparse(url if "://" in url else "https://" + url).hostname or url

    def check_scope(self, url, program=None):
        scope = self._scope(program)
        if not scope:
            return
        host = self._host(url)
        out = scope.get("out_of_scope", {})
        for pat in out.get("domains", []):
            if self._match_domain(host, pat):
                raise ScopeError(f"{host} out of scope ({pat})")
        path = urlparse(url if "://" in url else "https://" + url).path
        for ep in out.get("endpoints", []):
            if path.startswith(ep):
                raise ScopeError(f"{path} out of scope ({ep})")

    def is_in_scope(self, url, prog=None):
        try:
            self.check_scope(url, prog)
            return True
        except ScopeError:
            return False

    def program_rate_limit(self, prog):
        return min(float(self._scope(prog).get("rate_limit", self.rate_limit)), MAX_RATE)

    def excluded_vuln_types(self, prog):
        return self._scope(prog).get("out_of_scope", {}).get("excluded_vuln_types", [])

    def raw(self):
        return dict(self._data)


def load(path=None):
    if path is None:
        path = Path.home() / ".keres" / "config.yaml"
    if not path.exists():
        return Config(_DEFAULT.copy())
    with path.open() as f:
        data = yaml.safe_load(f) or {}
    return Config(_deep_merge(_DEFAULT.copy(), data))


def save(cfg, path=None):
    if path is None:
        path = Path.home() / ".keres" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        yaml.safe_dump(cfg.raw(), f)


def _deep_merge(base, override):
    for k, v in override.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            base[k] = _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def write_default(path=None):
    if path is None:
        path = Path.home() / ".keres" / "config.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        yaml.safe_dump(_DEFAULT, f)
    return path
