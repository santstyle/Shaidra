"""Request counters feeding the dashboard's LIVE STATS panel.

Shaidra's async pipeline is single-threaded, so plain attributes are enough;
httpx invokes the response hook on the event loop thread. The hook must never
raise (a stats failure may not abort a request), hence the suppress in the
recorder's caller in utils.http.
"""

from __future__ import annotations

_request_count = 0
_total_latency_ms = 0.0


def record_request(latency_ms: float) -> None:
    """Count one completed response and fold its latency into the running average."""
    global _request_count, _total_latency_ms
    _request_count += 1
    _total_latency_ms += latency_ms


def request_count() -> int:
    """Return how many responses have been recorded so far."""
    return _request_count


def average_ms() -> float:
    """Return the average response latency in milliseconds (0.0 when idle)."""
    if _request_count == 0:
        return 0.0
    return _total_latency_ms / _request_count


def reset() -> None:
    """Zero the counters; used by tests to stay order-independent."""
    global _request_count, _total_latency_ms
    _request_count = 0
    _total_latency_ms = 0.0
