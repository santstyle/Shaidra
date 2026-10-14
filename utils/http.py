"""Shared HTTP client factory so auth headers apply to every built-in request.

Every stage that talks to the target app directly creates its ``AsyncClient``
through :func:`make_http_client`, which bakes in the headers collected on the
CLI (``--cookie`` / ``--header``). That lets Shaidra scan authenticated areas
(session-cookie protected pages, IDOR endpoints behind login) without each
stage having to thread headers itself.
"""

from __future__ import annotations

from typing import Any

import httpx

from shaidra.core.models import ScanContext


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
    return httpx.AsyncClient(
        follow_redirects=follow_redirects,
        timeout=timeout,
        verify=verify,
        headers=headers,
        **kwargs,
    )
