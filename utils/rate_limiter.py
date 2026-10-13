"""Async token-bucket rate limiter for the checks Shaidra performs itself.

External tools rate-limit through their own flags; this limiter governs the
lightweight HTTP probes (CORS, open redirect, WAF fallback) that Shaidra runs
directly, so the whole run honors a single request-per-second budget.
"""

from __future__ import annotations

import asyncio
import time


class RateConfigError(Exception):
    """Raised when a limiter is created or reconfigured with a non-positive rate."""


class RateLimiter:
    """Token bucket. asyncio is used per the project spec (# noqa: ANYIO_OK)."""

    def __init__(self, rate: float, burst: float | None = None) -> None:
        if rate <= 0:
            raise RateConfigError("rate must be positive")
        self._rate = float(rate)
        self._capacity = float(burst) if burst is not None else max(1.0, float(rate))
        self._tokens = self._capacity
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    @property
    def rate(self) -> float:
        """Current refill rate in tokens (requests) per second."""
        return self._rate

    def set_rate(self, rate: float) -> None:
        """Change the refill rate, e.g. after WAF detection lowers the budget."""
        if rate <= 0:
            raise RateConfigError("rate must be positive")
        self._rate = float(rate)
        self._capacity = max(1.0, float(rate))
        self._tokens = min(self._tokens, self._capacity)

    async def acquire(self, tokens: float = 1.0) -> None:
        """Block until the requested number of tokens is available."""
        wanted = min(tokens, self._capacity)
        async with self._lock:
            while True:
                self._refill()
                if self._tokens >= wanted:
                    self._tokens -= wanted
                    return
                deficit = wanted - self._tokens
                await asyncio.sleep(deficit / self._rate)

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
            self._updated = now
