"""Per-target rate limiting ("50/minute" style sliding windows)."""
from __future__ import annotations

import re
import threading
import time

_RATE_RE = re.compile(r"^\s*(\d+)\s*/\s*(second|minute|hour)\s*$", re.IGNORECASE)

_UNIT_SECONDS = {"second": 1, "minute": 60, "hour": 3600}


def parse_rate(rate: str) -> tuple[int, int]:
    """Parse ``"50/minute"`` → ``(50, 60)`` (limit, window seconds).

    Raises ValueError on malformed input.
    """
    m = _RATE_RE.match(rate or "")
    if not m:
        raise ValueError(
            f"invalid rate limit string: {rate!r} (expected 'N/second|minute|hour')"
        )
    limit = int(m.group(1))
    unit = m.group(2).lower()
    if limit <= 0:
        raise ValueError(f"rate limit must be positive: {rate!r}")
    return limit, _UNIT_SECONDS[unit]


class RateLimiter:
    """Thread-safe per-key sliding-window rate limiter."""

    def __init__(self):
        self._lock = threading.Lock()
        self._limits: dict[str, tuple[float, float]] = {}
        self._timestamps: dict[str, list[float]] = {}

    def configure(self, key: str, rate: str) -> None:
        """Set the limit for *key* from a rate string."""
        limit, window = parse_rate(rate)
        with self._lock:
            self._limits[key] = (float(limit), float(window))

    def acquire(self, key: str, rate: str | None = None) -> float:
        """Reserve one slot for *key*; returns seconds slept (0 if none).

        Blocks (sleeps) until a slot is available within the window.
        Unconfigured keys are unlimited.
        """
        if rate is not None:
            self.configure(key, rate)
        with self._lock:
            spec = self._limits.get(key)
            if spec is None:
                return 0.0
            limit, window = spec
            now = time.monotonic()
            timestamps = [t for t in self._timestamps.get(key, []) if now - t < window]
            if len(timestamps) < limit:
                timestamps.append(now)
                self._timestamps[key] = timestamps
                return 0.0
            wait = max(0.0, window - (now - timestamps[0]))
        if wait > 0:
            time.sleep(wait)
        return self.acquire(key)

    def try_acquire(self, key: str) -> bool:
        """Non-blocking: True when a slot is free for *key*."""
        with self._lock:
            spec = self._limits.get(key)
            if spec is None:
                return True
            limit, window = spec
            now = time.monotonic()
            timestamps = [t for t in self._timestamps.get(key, []) if now - t < window]
            if len(timestamps) < limit:
                timestamps.append(now)
                self._timestamps[key] = timestamps
                return True
            return False
