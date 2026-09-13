import threading, time, logging
from typing import Dict, Optional

log = logging.getLogger(__name__)

class TokenBucket:
    def __init__(self, rate: float, capacity: Optional[float] = None):
        self._rate = rate
        self._capacity = capacity if capacity is not None else rate
        self._tokens = self._capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    @property
    def rate(self):
        return self._rate

    def set_rate(self, r):
        with self._lock:
            self._rate = max(0.1, r)
            self._capacity = max(self._capacity, r)

    def acquire(self, timeout: float = 60.0):
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                wait = (1.0 - self._tokens) / self._rate
            if time.monotonic() + wait > deadline:
                return False
            time.sleep(min(wait, 0.1))

    def throttle_back(self, factor: float = 0.5):
        with self._lock:
            self._rate = max(0.5, self._rate * factor)


_buckets: Dict[str, TokenBucket] = {}
_registry_lock = threading.Lock()
_default_rate = 10.0


def set_default_rate(r):
    global _default_rate
    _default_rate = min(r, 50)


def get_bucket(domain):
    with _registry_lock:
        if domain not in _buckets:
            _buckets[domain] = TokenBucket(_default_rate)
        return _buckets[domain]


def acquire(domain):
    return get_bucket(domain).acquire()


def throttle(domain):
    get_bucket(domain).throttle_back()


def set_domain_rate(domain, r):
    get_bucket(domain).set_rate(min(r, 50))
