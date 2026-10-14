"""API surface discovery and exposed-endpoint checks.

Two complementary sources feed this stage:

* A curated set of high-signal API paths (Swagger/OpenAPI documents, GraphQL,
  Spring Boot Actuator, OpenID discovery) is probed on every live in-scope host
  with Shaidra's own rate-limited httpx requests. A probe that answers with a
  success status and the marker text identifying that artefact is reported at
  its fixed severity.
* Under ``--extended``, kiterunner (``kiterunner`` or its ``kr`` alias) sweeps
  the API wordlist for additional routes when it is installed. Discovered
  routes are reported informationally.

Every request is a GET; nothing is written to the target.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, JsonValue, LogLevel, ScanContext, Severity
from shaidra.utils.http import make_http_client
from shaidra.utils.process import RunOptions, stream_lines
from shaidra.utils.rate_limiter import RateLimiter

STAGE: Final[str] = "API scan"
MAX_HOSTS: Final[int] = 50
TIMEOUT_SECONDS: Final[float] = 10.0
BODY_SNIFF: Final[int] = 4096
SUCCESS_CODES: Final[frozenset[int]] = frozenset({200, 201, 202, 203, 206})
_KR_NAMES: Final[tuple[str, ...]] = ("kiterunner", "kr")


@dataclass(frozen=True, slots=True)
class _Probe:
    """A single API path and the markers that confirm its exposure."""

    path: str
    title: str
    severity: Severity
    markers: tuple[str, ...]


_PROBES: Final[tuple[_Probe, ...]] = (
    _Probe("/swagger.json", "Exposed API documentation (Swagger)", Severity.MEDIUM, ("swagger", "openapi")),
    _Probe("/openapi.json", "Exposed API documentation (OpenAPI)", Severity.MEDIUM, ("openapi", "swagger")),
    _Probe("/api-docs", "Exposed API documentation", Severity.MEDIUM, ("swagger", "openapi", '"paths"')),
    _Probe("/v2/api-docs", "Exposed API documentation (v2)", Severity.MEDIUM, ("swagger", "openapi", '"paths"')),
    _Probe("/swagger-ui.html", "Exposed Swagger UI", Severity.LOW, ("swagger", "swagger-ui")),
    _Probe("/swagger/index.html", "Exposed Swagger UI", Severity.LOW, ("swagger", "swagger-ui")),
    _Probe("/graphql", "GraphQL endpoint exposed", Severity.LOW, ("graphql", "query", "data")),
    _Probe("/graphql", "GraphQL introspection enabled", Severity.MEDIUM, ("introspection",)),
    _Probe("/api/docs/", "Exposed API documentation (Swagger UI)", Severity.MEDIUM, ("swagger", "openapi")),
    _Probe(
        "/actuator/env",
        "Spring Boot actuator environment exposed",
        Severity.HIGH,
        ("propertysources", "activeprofiles", "systemproperties"),
    ),
    _Probe("/actuator", "Spring Boot actuator exposed", Severity.MEDIUM, ("_links", "actuator", "health")),
    _Probe(
        "/.well-known/openid-configuration",
        "OpenID Connect discovery document exposed",
        Severity.INFO,
        ("issuer", "authorization_endpoint"),
    ),
    _Probe("/api", "API root reachable", Severity.INFO, ()),
)


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Probe the curated API paths, then optionally sweep with kiterunner."""
    await bus.stage_start(STAGE)
    if not ctx.web_reachable:
        await bus.stage_skip(STAGE, "target not reachable")
        return
    targets = _targets(ctx)
    if not targets:
        await bus.stage_skip(STAGE, "no live in-scope hosts")
        return
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    found = await _probe_all(ctx, bus, targets, limiter)
    if ctx.extended:
        await _kiterunner(ctx, bus, targets)
    await bus.stage_done(STAGE, f"{found} exposed endpoint(s)")


def _targets(ctx: ScanContext) -> list[str]:
    """Return deduplicated in-scope base URLs, capped at MAX_HOSTS."""
    bases: list[str] = []
    if ctx.target_url and ctx.scope.in_scope(ctx.target_url):
        bases.append(ctx.target_url.rstrip("/"))
    for host in ctx.live_hosts():
        if len(bases) >= MAX_HOSTS:
            break
        if host.url is None or not ctx.scope.in_scope(host.host):
            continue
        base = host.url.rstrip("/")
        if base not in bases:
            bases.append(base)
    return bases[:MAX_HOSTS]


async def _probe_all(ctx: ScanContext, bus: EventBus, targets: list[str], limiter: RateLimiter) -> int:
    """Probe every curated path on every target, streaming findings as they hit."""
    total = len(targets) * len(_PROBES)
    current = 0
    found = 0
    async with make_http_client(ctx, follow_redirects=False, timeout=TIMEOUT_SECONDS) as client:
        for base in targets:
            for probe in _PROBES:
                current += 1
                finding = await _probe(client, limiter, base, probe)
                await bus.stage_progress(STAGE, current, total)
                if finding is None:
                    continue
                found += 1
                await bus.finding(finding)
    return found


async def _probe(client: httpx.AsyncClient, limiter: RateLimiter, base: str, probe: _Probe) -> Finding | None:
    """Send one GET and return a finding when the artefact is confirmed."""
    url = f"{base}{probe.path}"
    await limiter.acquire()
    try:
        response = await client.get(url, headers={"Accept": "application/json, */*"})
    except (httpx.HTTPError, TimeoutError):
        return None
    if response.status_code not in SUCCESS_CODES:
        return None
    body = _sniff(response.text)
    if not _confirmed(body, response.headers.get("content-type", ""), probe):
        return None
    return _finding(base, url, probe, response.status_code)


def _sniff(text: str) -> str:
    """Lowercase the first bytes of a response body for marker matching."""
    return text[:BODY_SNIFF].lower()


def _confirmed(body: str, content_type: str, probe: _Probe) -> bool:
    """Decide whether a response really exposes the probe's artefact."""
    if probe.markers:
        return any(marker in body for marker in probe.markers)
    if "json" in content_type.lower():
        return True
    stripped = body.lstrip()
    return stripped.startswith(("{", "["))


def _finding(base: str, url: str, probe: _Probe, status: int) -> Finding:
    """Build the normalized finding for one exposed endpoint."""
    return Finding(
        title=probe.title,
        severity=probe.severity,
        category=Category.API,
        host=_host_of(base),
        tool="shaidra",
        url=url,
        evidence=f"GET {url} -> {status}",
        description=(
            f"{url} answered HTTP {status} with content matching a known API artefact, "
            "so this endpoint is reachable without authentication."
        ),
        raw={"path": probe.path, "status": status},
    )


async def _kiterunner(ctx: ScanContext, bus: EventBus, targets: list[str]) -> None:
    """Sweep the API wordlist with kiterunner and report discovered routes."""
    wordlist = Path(ctx.config.wordlist_api)
    if not wordlist.is_file():
        await bus.log("kiterunner: api wordlist not found; skipping sweep", LogLevel.WARN)
        return
    tool = next((name for name in _KR_NAMES if ctx.has_tool(name)), None)
    if tool is None:
        await bus.stage_skip("kiterunner", "kiterunner not installed")
        return
    options = RunOptions(timeout=float(ctx.config.timeout_for("kiterunner")))
    found = 0
    for base in targets:
        argv = [tool, "scan", base, "-w", str(wordlist), "-q", "-o", "json"]
        async for line in stream_lines(argv, options):
            finding = _kr_finding(line, base)
            if finding is None:
                continue
            found += 1
            await bus.finding(finding)
    await bus.log(f"kiterunner: {found} route(s) discovered")


def _kr_finding(line: str, fallback_base: str) -> Finding | None:
    """Parse one kiterunner JSON line into an informational route finding."""
    payload = _load_object(line)
    if payload is None:
        return None
    route = (
        _text(payload.get("URL"))
        or _text(payload.get("url"))
        or _text(payload.get("Path"))
        or _text(payload.get("path"))
    )
    if not route:
        return None
    url = route if route.startswith(("http://", "https://")) else f"{fallback_base}{route}"
    method = _text(payload.get("Method")) or _text(payload.get("method"))
    status = _int(payload.get("Status") if "Status" in payload else payload.get("status"))
    return Finding(
        title="API route discovered",
        severity=Severity.INFO,
        category=Category.API,
        host=_host_of(url),
        tool="kiterunner",
        url=url,
        evidence=f"{method or 'GET'} {url} -> {status}" if status is not None else url,
        description="kiterunner discovered a reachable API route from the API wordlist.",
        raw=payload,
    )


def _load_object(line: str) -> dict[str, JsonValue] | None:
    try:
        payload: JsonValue = json.loads(line)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _text(value: JsonValue | None) -> str:
    return value if isinstance(value, str) else ""


def _int(value: JsonValue | None) -> int | None:
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _host_of(url: str) -> str:
    return urlsplit(url).hostname or url
