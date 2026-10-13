"""Open redirect checks using Shaidra's own httpx probes.

Candidate parameterized URLs come from ctx.crawled_urls (query strings only);
when none exist, live host base URLs are appended with each known redirect
parameter name. Each candidate parameter is set to an external marker
(``https://evil.example/`` or ``//evil.example``), the request is sent with
redirects disabled, and a 3xx Location header pointing at the external host
confirms the finding (MEDIUM). Same-host redirects are ignored. Total
requests are capped and every request is throttled through RateLimiter with
ctx.rate_limit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, ScanContext, Severity
from shaidra.utils.http import make_http_client
from shaidra.utils.rate_limiter import RateLimiter

STAGE: Final[str] = "open_redirect"
TOOL: Final[str] = "shaidra"
MAX_REQUESTS: Final[int] = 60
MAX_BASE_HOSTS: Final[int] = 3
TIMEOUT_SECONDS: Final[float] = 10.0
EXTERNAL_HOST: Final[str] = "evil.example"
MARKERS: Final[tuple[str, ...]] = (f"https://{EXTERNAL_HOST}/", f"//{EXTERNAL_HOST}")
PARAM_NAMES: Final[tuple[str, ...]] = (
    "url",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "next",
    "dest",
    "destination",
    "return",
    "returnUrl",
    "return_to",
    "continue",
    "target",
    "r",
    "u",
    "goto",
    "out",
    "view",
    "to",
    "link",
    "callback",
)


@dataclass(frozen=True, slots=True)
class _Probe:
    """One parameterized request to attempt."""

    url: str
    endpoint: str
    param: str
    marker: str


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Probe candidate endpoints for redirects to an external host."""
    await bus.stage_start(STAGE)
    if not ctx.web_reachable:
        await bus.stage_skip(STAGE, "target not reachable")
        return
    probes = _build_probes(ctx)
    if not probes:
        await bus.stage_skip(STAGE, "no candidate URLs to test")
        return
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    await bus.stage_progress(STAGE, 0, len(probes))
    reported: set[tuple[str, str]] = set()
    found = 0
    async with make_http_client(ctx, follow_redirects=False, timeout=TIMEOUT_SECONDS) as client:
        for current, probe in enumerate(probes, start=1):
            location = await _probe(client, limiter, probe)
            key = (probe.endpoint, probe.param.lower())
            if location is not None and key not in reported:
                reported.add(key)
                found += 1
                await bus.finding(_build_finding(probe, location))
            await bus.stage_progress(STAGE, current, len(probes))
    await bus.stage_done(STAGE, f"{found} open redirect(s) found")


def _build_probes(ctx: ScanContext) -> list[_Probe]:
    """Collect capped probes: crawled query URLs first, base URLs as fallback."""
    probes: list[_Probe] = []
    crawled = [url for url in ctx.crawled_urls if urlsplit(url).query]
    if crawled:
        seen: set[tuple[str, str]] = set()
        for url in crawled:
            if len(probes) >= MAX_REQUESTS:
                break
            if not ctx.scope.in_scope(url):
                continue
            _collect_crawled_probes(url, seen, probes)
    else:
        for base in _in_scope_bases(ctx):
            for param in PARAM_NAMES:
                for marker in MARKERS:
                    if len(probes) >= MAX_REQUESTS:
                        return probes
                    query = urlencode({param: marker})
                    probes.append(_Probe(url=f"{base}?{query}", endpoint=base, param=param, marker=marker))
    return probes


def _collect_crawled_probes(url: str, seen: set[tuple[str, str]], probes: list[_Probe]) -> None:
    """Append probes for every redirect-shaped parameter present in one crawled URL."""
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    names = {name for name, _ in pairs}
    for candidate in PARAM_NAMES:
        if len(probes) >= MAX_REQUESTS:
            return
        match_name = next((name for name in names if name.lower() == candidate.lower()), None)
        if match_name is None:
            continue
        dedup = (url, match_name.lower())
        if dedup in seen:
            continue
        seen.add(dedup)
        for marker in MARKERS:
            if len(probes) >= MAX_REQUESTS:
                return
            replaced = urlencode(
                [(name, marker if name == match_name else value) for name, value in pairs],
            )
            rebuilt = urlunsplit((parts.scheme, parts.netloc, parts.path, replaced, ""))
            probes.append(_Probe(url=rebuilt, endpoint=url, param=match_name, marker=marker))


def _in_scope_bases(ctx: ScanContext) -> list[str]:
    """Return up to MAX_BASE_HOSTS in-scope base URLs for the fallback probes."""
    bases: list[str] = []
    if ctx.target_url and ctx.scope.in_scope(ctx.target_url):
        bases.append(ctx.target_url.rstrip("/"))
    for host in ctx.live_hosts():
        if len(bases) >= MAX_BASE_HOSTS:
            break
        if host.url is None or not ctx.scope.in_scope(host.host):
            continue
        base = host.url.rstrip("/")
        if base not in bases:
            bases.append(base)
    return bases[:MAX_BASE_HOSTS]


async def _probe(client: httpx.AsyncClient, limiter: RateLimiter, probe: _Probe) -> str | None:
    """Request one probe; return the Location header when it points external."""
    await limiter.acquire()
    try:
        response = await client.get(probe.url)
    except (httpx.HTTPError, TimeoutError):
        return None
    if not 300 <= response.status_code < 400:
        return None
    location = response.headers.get("location")
    if location is None or not _points_external(location):
        return None
    return location


def _points_external(location: str) -> bool:
    """Return whether a Location header targets the external marker host."""
    candidate = location.strip()
    if not candidate:
        return False
    parts = urlsplit(candidate)
    hostname = parts.hostname
    return hostname is not None and hostname.lower() == EXTERNAL_HOST


def _build_finding(probe: _Probe, location: str) -> Finding:
    """Assemble the normalized finding for one vulnerable endpoint."""
    host = urlsplit(probe.endpoint).hostname or urlsplit(probe.url).hostname or ""
    return Finding(
        title="Open redirect",
        severity=Severity.MEDIUM,
        category=Category.REDIRECT,
        host=host,
        tool=TOOL,
        url=probe.endpoint,
        evidence=f"{probe.url} -> Location: {location}",
        description=(
            f"The {probe.param} parameter on {probe.endpoint} accepts the "
            f"external value {probe.marker} and redirects the browser to "
            f"{location}, enabling phishing and token-theft via crafted links."
        ),
        raw={"param": probe.param, "marker": probe.marker, "location": location},
    )
