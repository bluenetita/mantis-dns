"""Sliding-window in-memory rate limiter.

Used on the login endpoint (H-7) to blunt credential-stuffing attacks.
Single-process only — good enough for the current Docker Compose deployment.
Replace with Redis-backed slowapi when horizontal scaling lands.
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock

from fastapi import HTTPException, Request


class _SlidingWindowLimiter:
    def __init__(self, max_requests: int, window_secs: int) -> None:
        self._max = max_requests
        self._window = window_secs
        self._timestamps: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

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


_login_limiter = _SlidingWindowLimiter(max_requests=10, window_secs=60)


def login_rate_limit(request: Request) -> None:
    """FastAPI dependency — enforces 10 login attempts/minute per source IP."""
    forwarded = request.headers.get("X-Forwarded-For")
    ip = (
        forwarded.split(",")[0].strip()
        if forwarded
        else (request.client.host if request.client else "unknown")
    )
    _login_limiter.check(ip)
