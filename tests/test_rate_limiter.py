"""Tests for the async token-bucket rate limiter.

The limiter governs every built-in HTTP probe, and `set_rate` is how a WAF
detection halves the request budget mid-run — both paths must reject
non-positive rates so the pipeline can never spin on a zero rate.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from shaidra.utils.rate_limiter import RateConfigError, RateLimiter


class TestConstruction:
    def test_non_positive_rate_raises(self) -> None:
        for rate in (0, -1, -0.5):
            with pytest.raises(RateConfigError, match="rate must be positive"):
                RateLimiter(rate)

    def test_rate_property_reports_configured_rate(self) -> None:
        assert RateLimiter(40).rate == 40.0
        assert RateLimiter(0.5).rate == 0.5

    def test_default_burst_at_least_one_token(self) -> None:
        limiter = RateLimiter(0.1)
        started = time.monotonic()
        asyncio.run(limiter.acquire())
        # Capacity is max(1, rate) = 1, so the first token is free.
        assert time.monotonic() - started < 0.5

    def test_explicit_burst_is_honoured(self) -> None:
        limiter = RateLimiter(100, burst=5)
        started = time.monotonic()
        for _ in range(5):
            asyncio.run(limiter.acquire())
        assert time.monotonic() - started < 0.5


class TestSetRate:
    def test_non_positive_rate_raises(self) -> None:
        limiter = RateLimiter(40)
        for rate in (0, -3):
            with pytest.raises(RateConfigError, match="rate must be positive"):
                limiter.set_rate(rate)
        assert limiter.rate == 40.0  # unchanged after failed reconfigure

    def test_set_rate_updates_rate_and_shrinks_burst(self) -> None:
        limiter = RateLimiter(40, burst=40)
        limiter.set_rate(20)
        assert limiter.rate == 20.0
        # Capacity is clamped to max(1, rate): tokens cannot exceed it.
        started = time.monotonic()
        asyncio.run(limiter.acquire())
        assert time.monotonic() - started < 0.5

    def test_lowered_rate_slows_refill(self) -> None:
        limiter = RateLimiter(1000, burst=1)
        limiter.set_rate(1)
        asyncio.run(limiter.acquire())  # drain the single token
        started = time.monotonic()
        asyncio.run(limiter.acquire())  # must wait for a refill at 1 req/s
        elapsed = time.monotonic() - started
        assert elapsed >= 0.4


class TestAcquire:
    def test_tokens_are_consumed_then_refill(self) -> None:
        limiter = RateLimiter(100, burst=2)
        started = time.monotonic()
        for _ in range(2):
            asyncio.run(limiter.acquire())
        assert time.monotonic() - started < 0.5  # burst covers both

    def test_request_larger_than_capacity_is_clamped(self) -> None:
        limiter = RateLimiter(2, burst=2)
        started = time.monotonic()
        asyncio.run(limiter.acquire(tokens=10))  # clamped to capacity=2
        assert time.monotonic() - started < 0.5

    def test_concurrent_acquires_all_complete(self) -> None:
        limiter = RateLimiter(50, burst=1)

        async def _burst(count: int) -> None:
            await asyncio.gather(*(limiter.acquire() for _ in range(count)))

        started = time.monotonic()
        asyncio.run(_burst(10))
        assert time.monotonic() - started < 5.0
