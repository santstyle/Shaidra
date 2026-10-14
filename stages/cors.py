"""CORS misconfiguration checks using Shaidra's own httpx probes.

For every live in-scope host, a GET is sent with a crafted Origin header
(``https://evil.example`` and ``null``). The response's
Access-Control-Allow-Origin (ACAO) and Access-Control-Allow-Credentials
(ACAC) headers decide the verdict:

* ACAO reflects the attacker origin or is ``*`` AND ACAC is ``true`` -> HIGH
* ACAO reflects the exact attacker origin, no credentials           -> MEDIUM
* ACAO is ``null`` for a ``null`` Origin                            -> LOW
* ``*`` without credentials, a fixed allowlist, or no ACAO          -> no finding

One finding is emitted per vulnerable host, at the highest verdict reached.
Every request is throttled through RateLimiter with ctx.rate_limit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import (
    SEVERITY_RANK,
    Category,
    Finding,
    Host,
    ScanContext,
    Severity,
)
from shaidra.utils.http import make_http_client
from shaidra.utils.rate_limiter import RateLimiter

STAGE: Final[str] = "cors"
TOOL: Final[str] = "shaidra"
MAX_HOSTS: Final[int] = 100
TIMEOUT_SECONDS: Final[float] = 10.0
PROBE_ORIGINS: Final[tuple[str, ...]] = ("https://evil.example", "null")
NULL_ORIGIN: Final[str] = "null"
WILDCARD: Final[str] = "*"


class CorsVerdict(StrEnum):
    """Outcome of a single Origin probe against one host."""

    SAFE = "safe"
    NULL_REFLECTION = "null_reflection"
    REFLECT_NO_CREDS = "reflect_no_creds"
    REFLECT_WITH_CREDS = "reflect_with_creds"


@dataclass(frozen=True, slots=True)
class _ProbeResult:
    """Headers and verdict from one Origin probe."""

    origin: str
    acao: str | None
    acac: str | None
    verdict: CorsVerdict


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Probe every live in-scope host for permissive CORS."""
    await bus.stage_start(STAGE)
    hosts = _in_scope_live_hosts(ctx)
    if not hosts:
        await bus.stage_skip(STAGE, "no live in-scope hosts")
        return
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    total = len(hosts) * len(PROBE_ORIGINS)
    current = 0
    found = 0
    async with make_http_client(ctx, follow_redirects=False, timeout=TIMEOUT_SECONDS) as client:
        for host in hosts:
            best: _ProbeResult | None = None
            for origin in PROBE_ORIGINS:
                result = await _probe_origin(client, limiter, host, origin)
                current += 1
                await bus.stage_progress(STAGE, current, total)
                if result is None or result.verdict is CorsVerdict.SAFE:
                    continue
                if best is None or _rank(result) > _rank(best):
                    best = result
            if best is not None:
                found += 1
                await bus.finding(_build_finding(host, best))
    await bus.stage_done(STAGE, f"{found} vulnerable host(s)")


def _in_scope_live_hosts(ctx: ScanContext) -> list[Host]:
    """Return live hosts with a URL that are in scope, capped at MAX_HOSTS."""
    hosts: list[Host] = []
    for host in ctx.live_hosts():
        if len(hosts) >= MAX_HOSTS:
            break
        if host.url is None or not ctx.scope.in_scope(host.host):
            continue
        hosts.append(host)
    return hosts


async def _probe_origin(
    client: httpx.AsyncClient,
    limiter: RateLimiter,
    host: Host,
    origin: str,
) -> _ProbeResult | None:
    """Send one GET with the given Origin header and classify the response."""
    url = host.url
    if url is None:
        return None
    await limiter.acquire()
    try:
        response = await client.get(url, headers={"Origin": origin})
    except (httpx.HTTPError, TimeoutError):
        return None
    acao = response.headers.get("access-control-allow-origin")
    acac = response.headers.get("access-control-allow-credentials")
    return _ProbeResult(origin=origin, acao=acao, acac=acac, verdict=_classify(origin, acao, acac))


def _classify(origin: str, acao: str | None, acac: str | None) -> CorsVerdict:
    """Map ACAO/ACAC header values for one sent Origin to a verdict."""
    if acao is None:
        return CorsVerdict.SAFE
    value = acao.strip()
    credentials = acac is not None and acac.strip().lower() == "true"
    if origin == NULL_ORIGIN:
        match value:
            case "null":
                return CorsVerdict.NULL_REFLECTION
            case _:
                return CorsVerdict.SAFE
    reflected = value == origin
    if (reflected or value == WILDCARD) and credentials:
        return CorsVerdict.REFLECT_WITH_CREDS
    if reflected:
        return CorsVerdict.REFLECT_NO_CREDS
    return CorsVerdict.SAFE


def _severity_for(verdict: CorsVerdict) -> Severity:
    """Map a verdict to its normalized severity."""
    match verdict:
        case CorsVerdict.REFLECT_WITH_CREDS:
            return Severity.HIGH
        case CorsVerdict.REFLECT_NO_CREDS:
            return Severity.MEDIUM
        case CorsVerdict.NULL_REFLECTION:
            return Severity.LOW
        case CorsVerdict.SAFE:
            return Severity.INFO


def _rank(result: _ProbeResult) -> int:
    """Severity rank used to pick the worst verdict for a host."""
    return SEVERITY_RANK[_severity_for(result.verdict)]


def _title_and_description(result: _ProbeResult) -> tuple[str, str]:
    """Build the finding title and description for a verdict."""
    match result.verdict:
        case CorsVerdict.REFLECT_WITH_CREDS:
            return (
                "CORS misconfiguration: reflected origin with credentials",
                (
                    f"The server reflects the attacker Origin {result.origin} in "
                    "Access-Control-Allow-Origin and sets "
                    "Access-Control-Allow-Credentials: true, allowing cross-origin "
                    "reads of authenticated responses from any website."
                ),
            )
        case CorsVerdict.REFLECT_NO_CREDS:
            return (
                "CORS misconfiguration: reflected origin",
                (
                    f"The server reflects the attacker Origin {result.origin} in "
                    "Access-Control-Allow-Origin instead of enforcing an allowlist, "
                    "allowing cross-origin reads of responses from any website."
                ),
            )
        case CorsVerdict.NULL_REFLECTION:
            return (
                "CORS misconfiguration: null origin reflection",
                (
                    "The server answers the null Origin with "
                    "Access-Control-Allow-Origin: null, allowing sandboxed frames "
                    "and data: URLs to read responses cross-origin."
                ),
            )
        case CorsVerdict.SAFE:
            return ("CORS misconfiguration", "No misconfiguration detected.")


def _format_headers(result: _ProbeResult) -> str:
    """Render the offending Origin and response headers for evidence."""
    acao = result.acao if result.acao is not None else "(absent)"
    acac = result.acac if result.acac is not None else "(absent)"
    return (
        f"Origin: {result.origin} -> "
        f"Access-Control-Allow-Origin: {acao}; "
        f"Access-Control-Allow-Credentials: {acac}"
    )


def _build_finding(host: Host, result: _ProbeResult) -> Finding:
    """Assemble the normalized finding for one vulnerable host."""
    title, description = _title_and_description(result)
    return Finding(
        title=title,
        severity=_severity_for(result.verdict),
        category=Category.CORS,
        host=host.host,
        tool=TOOL,
        url=host.url,
        evidence=_format_headers(result),
        description=description,
        raw={
            "origin": result.origin,
            "acao": result.acao,
            "acac": result.acac,
            "verdict": result.verdict.value,
        },
    )
