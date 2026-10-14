"""Shared HTTP client factory so auth headers apply to every built-in request.

Every stage that talks to the target app directly creates its ``AsyncClient``
through :func:`make_http_client`, which bakes in the headers collected on the
CLI (``--cookie`` / ``--header``). That lets Shaidra scan authenticated areas
(session-cookie protected pages, IDOR endpoints behind login) without each
stage having to thread headers itself.
"""

from __future__ import annotations

import contextlib
from typing import Any

import httpx

from shaidra.core.models import ScanContext
from shaidra.utils.stats import record_request


async def _record_response(response: httpx.Response) -> None:
    """Feed one response's latency into the dashboard stats; never raise.

    Must be a coroutine: httpx dispatches AsyncClient hooks via await, and a
    sync callable can break the request pipeline. ``response.elapsed`` is only
    valid after the body has been read, so the hook awaits ``aread()`` first
    (the buffered content stays available to the caller). A stats failure may
    not abort the request that just succeeded, so errors are swallowed.
    """
    with contextlib.suppress(Exception):
        await response.aread()
        record_request(response.elapsed.total_seconds() * 1000.0)


def make_http_client(
    ctx: ScanContext,
    *,
    follow_redirects: bool = False,
    timeout: float = 10.0,
    verify: bool = True,
    **kwargs: Any,
) -> httpx.AsyncClient:
    """Build an :class:`httpx.AsyncClient` carrying the scan's request headers.

    ``ctx.request_headers`` is injected as the default ``headers`` so every
    request the stage sends is authenticated the same way; passing
    ``headers=...`` in ``kwargs`` still overrides it per call.
    """
    headers = dict(ctx.request_headers) if ctx.request_headers else None
    if "headers" in kwargs and kwargs["headers"] is not None:
        merged = dict(headers or {})
        merged.update(kwargs.pop("headers"))
        headers = merged
    # Merge with any caller-supplied hooks instead of clobbering them; none
    # exist today, but a silent override would be a nasty surprise later.
    hooks = dict(kwargs.pop("event_hooks", None) or {})
    response_hooks = list(hooks.get("response", ()))
    response_hooks.append(_record_response)
    hooks["response"] = response_hooks
    return httpx.AsyncClient(
        follow_redirects=follow_redirects,
        timeout=timeout,
        verify=verify,
        headers=headers,
        event_hooks=hooks,
        **kwargs,
    )
