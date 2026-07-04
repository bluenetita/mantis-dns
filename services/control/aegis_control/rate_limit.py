"""Sliding-window in-memory rate limiter.

Used on the login endpoint (H-7) to blunt credential-stuffing attacks.
Single-process only — good enough for the current Docker Compose deployment.
Replace with Redis-backed slowapi when horizontal scaling lands.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException, Request

# X-Forwarded-For is attacker-controlled unless it's overwritten by a proxy
# we trust — set this to the reverse proxy's IP(s) so the login rate limiter
# keys on the real client IP rather than a header any client can rotate to
# dodge the limit. Empty by default: no reverse proxy in the compose
# deployment, so XFF is never trusted (falls back to the direct peer IP).
_TRUSTED_PROXY_IPS = {
    ip.strip() for ip in os.environ.get("AEGIS_TRUSTED_PROXY_IPS", "").split(",") if ip.strip()
}


_SWEEP_EVERY_N_CALLS = 1000


class _SlidingWindowLimiter:
    def __init__(self, max_requests: int, window_secs: int) -> None:
        self._max = max_requests
        self._window = window_secs
        self._timestamps: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        self._calls_since_sweep = 0

    def check(self, key: str) -> None:
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            ts = self._timestamps[key]
            while ts and ts[0] < cutoff:
                ts.pop(0)
            if len(ts) >= self._max:
                raise HTTPException(429, "too many login attempts — please wait before trying again")
            ts.append(now)

            # An IP's entry only gets pruned when *that same IP* calls check()
            # again, so one that stops attacking (or a fixed set of scanner
            # IPs, then never again) leaves a dead dict entry forever —
            # unbounded growth keyed on every distinct source IP ever seen.
            # Periodically sweep every key, not just the current one.
            self._calls_since_sweep += 1
            if self._calls_since_sweep >= _SWEEP_EVERY_N_CALLS:
                self._calls_since_sweep = 0
                stale = [k for k, v in self._timestamps.items() if not v or v[-1] < cutoff]
                for k in stale:
                    del self._timestamps[k]


_login_limiter = _SlidingWindowLimiter(max_requests=10, window_secs=60)


def login_rate_limit(request: Request) -> None:
    """FastAPI dependency — enforces 10 login attempts/minute per source IP.

    X-Forwarded-For is only honored when the direct peer is a configured
    trusted proxy (AEGIS_TRUSTED_PROXY_IPS); otherwise it's client-controlled
    and would let an attacker rotate it to dodge the limit entirely.
    """
    direct_ip = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded and direct_ip in _TRUSTED_PROXY_IPS:
        ip = forwarded.split(",")[0].strip()
    else:
        ip = direct_ip
    _login_limiter.check(ip)
