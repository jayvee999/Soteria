import itertools, logging, time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import httpx
from . import database as db, rate_limiter
from .config import Config, ScopeError

log = logging.getLogger(__name__)

_CDN_HEADERS = ["cf-ray", "x-amz-cf-id", "x-cache", "x-served-by"]
_CDN_SERVERS = ["cloudflare", "cloudfront", "fastly", "akamai"]


def _detect_cdn(resp):
    h = {k.lower(): v.lower() for k, v in resp.headers.items()}
    for hdr in _CDN_HEADERS:
        if hdr in h:
            return True
    return any(c in h.get("server", "") for c in _CDN_SERVERS)


class Client:
    def __init__(self, cfg: Config, program=None, operator=None):
        self._cfg = cfg
        self._program = program
        self._operator = operator
        self._ua = itertools.cycle(cfg.user_agents)
        self._s = httpx.Client(timeout=cfg.timeout, follow_redirects=False, verify=False)

    def request(self, method, url, headers=None, **kw):
        self._cfg.check_scope(url, self._program)
        domain = urlparse(url).hostname or url
        rate_limiter.acquire(domain)
        merged = {"User-Agent": next(self._ua)}
        if headers:
            merged.update(headers)
        try:
            resp = self._s.request(method, url, headers=merged, **kw)
        except httpx.TimeoutException:
            db.log_action("http_timeout", target=url, status="timeout", operator=self._operator)
            raise
        if resp.status_code == 429:
            rate_limiter.throttle(domain)
        db.log_action("http_request", target=url, command=f"{method} {url}",
                      status=str(resp.status_code), operator=self._operator)
        return resp

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def close(self):
        self._s.close()


def probe_alive(urls, cfg, program=None):
    results = []
    with Client(cfg, program=program) as c:
        for url in urls:
            try:
                r = c.head(url)
                results.append((url, r.status_code, _detect_cdn(r)))
            except Exception:
                pass
    return results
