"""Misconfiguration checks: directly exposed files plus optional tool sweeps.

Shaidra probes a fixed list of well-known exposure files with its own httpx
client (rate limited), then optionally runs nuclei and testssl. Probes are
bounded by request and finding caps; missing tools degrade silently.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Final
from urllib.parse import urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, Host, JsonValue, ScanContext, Severity
from shaidra.utils.process import RunOptions, run_tool, stream_lines
from shaidra.utils.rate_limiter import RateLimiter

STAGE_NAME: Final[str] = "Misconfiguration"
_HTTP_TIMEOUT: Final[float] = 10.0
_MAX_HOSTS: Final[int] = 5
_MAX_PROBE_REQUESTS: Final[int] = 60
_MAX_FINDINGS: Final[int] = 30
_MAX_NUCLEI_FINDINGS: Final[int] = 30
_MAX_TLS_FINDINGS: Final[int] = 5
_BODY_CAP: Final[int] = 16384

_EXPOSURE_PATHS: Final[tuple[str, ...]] = (
    ".git/config", ".env", ".htaccess", "phpinfo.php", "server-status",
    ".DS_Store", "backup.zip", "config.php~", "web.config", "Dockerfile",
)
_HIGH_EXPOSURES: Final[frozenset[str]] = frozenset({".env", ".git/config"})
_HTACCESS_MARKERS: Final[tuple[str, ...]] = (
    "RewriteRule", "RewriteEngine", "Require ", "Order allow", "Deny from",
)
_ENV_LINE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", re.MULTILINE)
_ANSI: Final[re.Pattern[str]] = re.compile(r"\x1b\[[0-9;]*m")
_TLS_PROTOCOL: Final[re.Pattern[str]] = re.compile(r"\b(SSLv[23]|TLS 1\.[01])\b")


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Probe live hosts for exposed files, then run nuclei/testssl if present."""
    await bus.stage_start(STAGE_NAME)
    bases = _in_scope_bases(ctx)
    if not bases:
        await bus.stage_skip(STAGE_NAME, "no live in-scope hosts to probe")
        return
    tools_available = ctx.has_tool("nuclei") or _testssl_bin(ctx) is not None
    found = await _probe_exposures(ctx, bus, bases)
    found += await _via_nuclei(ctx, bus, bases)
    found += await _via_testssl(ctx, bus, bases[0])
    if found == 0 and not tools_available:
        await bus.stage_skip(STAGE_NAME, "no exposure confirmed and nuclei/testssl not installed")
        return
    await bus.stage_done(STAGE_NAME, f"{found} misconfiguration findings")


def _in_scope_bases(ctx: ScanContext) -> list[str]:
    bases: list[str] = []
    for host in ctx.live_hosts():
        if not ctx.scope.in_scope(host.host):
            continue
        base = _base_url(host)
        if base not in bases:
            bases.append(base)
        if len(bases) >= _MAX_HOSTS:
            break
    if not bases and ctx.scope.in_scope(ctx.target_url):
        bases.append(ctx.target_url.rstrip("/"))
    return bases


def _base_url(host: Host) -> str:
    if host.url is not None:
        return host.url.rstrip("/")
    netloc = host.host if host.port in (None, 80, 443) else f"{host.host}:{host.port}"
    return f"{host.scheme or 'https'}://{netloc}"


async def _probe_exposures(ctx: ScanContext, bus: EventBus, bases: Sequence[str]) -> int:
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    total = len(bases) * len(_EXPOSURE_PATHS)
    requests = 0
    found = 0
    async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=False) as client:
        for base in bases:
            host = urlsplit(base).hostname or ctx.target
            for path in _EXPOSURE_PATHS:
                if requests >= _MAX_PROBE_REQUESTS or found >= _MAX_FINDINGS:
                    return found
                requests += 1
                await bus.stage_progress(STAGE_NAME, requests, total)
                await limiter.acquire()
                status, body = await _bounded_get(client, f"{base}/{path}")
                if not _confirmed(path, status, body):
                    continue
                found += 1
                await bus.finding(
                    Finding(
                        title=f"Exposed file: {path}",
                        severity=Severity.HIGH if path in _HIGH_EXPOSURES else Severity.MEDIUM,
                        category=Category.MISCONFIG,
                        host=host,
                        tool="shaidra",
                        evidence=f"HTTP {status}, {len(body)} bytes",
                        url=f"{base}/{path}",
                        description="A well-known sensitive file is reachable and its content matches the expected signature.",
                        raw={"status": status, "path": path},
                    )
                )
    return found


async def _bounded_get(client: httpx.AsyncClient, url: str) -> tuple[int, bytes]:
    try:
        async with client.stream("GET", url) as response:
            buffer = bytearray()
            async for chunk in response.aiter_bytes():
                buffer.extend(chunk)
                if len(buffer) >= _BODY_CAP:
                    break
            return response.status_code, bytes(buffer)
    except httpx.HTTPError:
        return 0, b""


def _confirmed(path: str, status: int, body: bytes) -> bool:
    if status != 200 or not body:
        return False
    text = body.decode("utf-8", "replace")
    match path:
        case ".env": return not text.lstrip().startswith("<") and _ENV_LINE.search(text) is not None
        case ".git/config": return "[core]" in text
        case ".htaccess": return any(marker in text for marker in _HTACCESS_MARKERS)
        case "phpinfo.php": return "phpinfo" in text.lower()
        case "server-status": return "apache server status" in text.lower()
        case ".DS_Store": return b"Bud1" in body[:32] or body[:4] == b"\x00\x00\x00\x01"
        case "backup.zip": return body[:4] == b"PK\x03\x04"
        case "config.php~": return "<?php" in text
        case "web.config": return "<configuration" in text.lower()
        case "Dockerfile": return text.lstrip().upper().startswith("FROM ")
        case _: return False


async def _via_nuclei(ctx: ScanContext, bus: EventBus, bases: Sequence[str]) -> int:
    if not ctx.has_tool("nuclei"):
        return 0
    argv = [
        "nuclei", "-silent", "-nc", "-jsonl",
        "-tags", "exposure,misconfig",
        "-rate-limit", str(max(1, ctx.rate_limit)),
        "-u", ",".join(bases),
    ]
    options = RunOptions(timeout=ctx.config.timeout_for("nuclei"))
    found = 0
    async for line in stream_lines(argv, options):
        if found >= _MAX_NUCLEI_FINDINGS:
            break
        finding = _nuclei_finding(line, ctx)
        if finding is None:
            continue
        found += 1
        await bus.finding(finding)
    return found


def _nuclei_finding(line: str, ctx: ScanContext) -> Finding | None:
    try:
        payload: JsonValue = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    info = payload.get("info")
    if not isinstance(info, dict):
        return None
    name = info.get("name")
    if not isinstance(name, str) or not name:
        return None
    matched = payload.get("matched-at")
    matched_url = matched if isinstance(matched, str) else ""
    template = payload.get("template-id") or payload.get("templateID")
    raw_severity = info.get("severity")
    return Finding(
        title=name,
        severity=_severity(raw_severity if isinstance(raw_severity, str) else ""),
        category=Category.MISCONFIG,
        host=urlsplit(matched_url).hostname or ctx.target,
        tool="nuclei",
        evidence=line[:300],
        url=matched_url or None,
        description="The nuclei exposure/misconfig tag set matched this host.",
        template=template if isinstance(template, str) else None,
    )


def _severity(raw: str) -> Severity:
    match raw.lower():
        case "critical": return Severity.CRITICAL
        case "high": return Severity.HIGH
        case "medium": return Severity.MEDIUM
        case "low": return Severity.LOW
        case "info": return Severity.INFO
        case _: return Severity.UNKNOWN


def _testssl_bin(ctx: ScanContext) -> str | None:
    if ctx.has_tool("testssl.sh"):
        return "testssl.sh"
    if ctx.has_tool("testssl"):
        return "testssl"
    return None


async def _via_testssl(ctx: ScanContext, bus: EventBus, base: str) -> int:
    binary = _testssl_bin(ctx)
    if binary is None:
        return 0
    argv = [binary, "--quiet", "--warnings", "off", base]
    options = RunOptions(timeout=ctx.config.timeout_for("testssl"))
    result = await run_tool(argv, options)
    host = urlsplit(base).hostname or ctx.target
    found = 0
    for protocol, evidence in _weak_tls(result.stdout):
        if found >= _MAX_TLS_FINDINGS:
            break
        found += 1
        await bus.finding(
            Finding(
                title=f"Weak TLS protocol enabled: {protocol}",
                severity=Severity.MEDIUM,
                category=Category.MISCONFIG,
                host=host,
                tool=binary,
                evidence=evidence[:200],
                url=base,
                description="testssl reported a deprecated protocol or weak TLS configuration.",
            )
        )
    return found


def _weak_tls(stdout: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in _ANSI.sub("", stdout).splitlines():
        line = raw.strip()
        protocol = _TLS_PROTOCOL.search(line)
        if protocol is None:
            continue
        lowered = line.lower()
        if "not offered" in lowered or "not supported" in lowered or "rejected" in lowered:
            continue
        if "offered" not in lowered and "vulnerable" not in lowered and "accepted" not in lowered:
            continue
        name = protocol.group(1)
        if name in seen:
            continue
        seen.add(name)
        hits.append((name, line))
    return hits
