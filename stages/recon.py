"""Stage 1: subdomain enumeration and live-host probing.

`run` discovers candidate hosts (subfinder/assetfinder, or a single seeded
host for bare-IP targets) and confirms liveness with ProjectDiscovery httpx,
falling back to Shaidra's own httpx library when the Go tool is missing.
`scan_ports` runs naabu against the target and reports admin/database ports.
"""

from __future__ import annotations

import asyncio
import html as html_lib
import json
import re
from typing import Final
from urllib.parse import urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, Host, LogLevel, ScanContext, Severity
from shaidra.utils.process import RunOptions, run_tool, stream_lines
from shaidra.utils.rate_limiter import RateLimiter

STAGE: Final[str] = "recon"
PORT_STAGE: Final[str] = "port-scan"
FALLBACK_HOST_CAP: Final[int] = 100
FALLBACK_TIMEOUT: Final[float] = 10.0
FALLBACK_CONCURRENCY: Final[int] = 10
_TITLE_RE: Final[re.Pattern[str]] = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_ADMIN_PORTS: Final[dict[int, str]] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
    2375: "Docker API",
    5900: "VNC",
}


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Enumerate subdomains, probe for liveness, and record live hosts."""
    await bus.stage_start(STAGE)
    base = _bare_host(ctx.target)
    seeded = urlsplit(ctx.target_url)
    candidates: list[Host] = [
        Host(host=base, url=ctx.target_url, scheme=seeded.scheme, port=seeded.port, source="target")
    ]
    if _is_bare_ip(base):
        await bus.log("Target is a bare IP address; subdomain enumeration skipped.", LogLevel.INFO)
    else:
        seen: set[str] = {base}
        for name in await _enumerate_subdomains(ctx, bus, base):
            if name not in seen:
                seen.add(name)
                candidates.append(Host(host=name, source="subdomain-enum"))
    if ctx.has_tool("httpx") and await _httpx_is_pd(ctx):
        live = await _probe_with_pd_httpx(ctx, bus, candidates)
    else:
        live = await _probe_with_python_httpx(ctx, bus, candidates)
    for host in live:
        ctx.add_host(host)
        await bus.host(host)
    await bus.stage_done(STAGE, f"{len(live)} live host(s) out of {len(candidates)} candidate(s)")


async def scan_ports(ctx: ScanContext, bus: EventBus) -> None:
    """Scan top ports with naabu and report interesting open services."""
    if not ctx.has_tool("naabu"):
        await bus.stage_skip(PORT_STAGE, "naabu not installed")
        return
    await bus.stage_start(PORT_STAGE)
    argv = ["naabu", "-host", _bare_host(ctx.target), "-top-ports", "1000", "-silent", "-rate", str(ctx.rate_limit)]
    opts = RunOptions(timeout=float(ctx.config.timeout_for("naabu", 600)))
    found = 0
    async for line in stream_lines(argv, opts):
        parsed = _parse_host_port(line)
        if parsed is None:
            continue
        key, port = parsed
        if not ctx.scope.in_scope(key):
            continue
        matched = _match_host(ctx, key)
        if matched is None:
            continue
        found += 1
        if matched.port is None:
            matched.port = port
        await bus.stage_progress(PORT_STAGE, found, 0)
        service = _ADMIN_PORTS.get(port)
        if service is not None:
            await bus.finding(
                Finding(
                    title=f"Open {service} port {port}",
                    severity=Severity.INFO,
                    category=Category.RECON,
                    host=matched.host,
                    tool="naabu",
                    evidence=f"{key}:{port}",
                    url=matched.url,
                    description=f"Port {port} ({service}) is reachable on {key}.",
                )
            )
    await bus.stage_done(PORT_STAGE, f"{found} open port(s) found")


async def _enumerate_subdomains(ctx: ScanContext, bus: EventBus, base: str) -> list[str]:
    """Run the installed enum tools and return sorted, in-scope hostnames."""
    argvs: list[list[str]] = []
    if ctx.has_tool("subfinder"):
        argvs.append(["subfinder", "-d", base, "-silent"])
    if ctx.has_tool("assetfinder"):
        argvs.append(["assetfinder", "--subs-only", base])
    if not argvs:
        await bus.log("Neither subfinder nor assetfinder installed; only the target host will be probed.", LogLevel.WARN)
        return []
    results = await asyncio.gather(*(run_tool(argv, RunOptions(timeout=_tool_timeout(ctx, argv[0]))) for argv in argvs))
    merged: set[str] = set()
    for result in results:
        if not result.ok:
            await bus.log(f"{result.tool} failed (rc={result.returncode}): {result.stderr.strip()}", LogLevel.WARN)
            continue
        merged.update(line.strip() for line in result.stdout.splitlines() if line.strip())
    scoped = sorted(name for name in merged if ctx.scope.in_scope(name))
    await bus.log(f"Subdomain enumeration found {len(scoped)} in-scope candidate(s).")
    return scoped


def _tool_timeout(ctx: ScanContext, tool: str) -> float:
    return float(ctx.config.timeout_for(tool))


async def _httpx_is_pd(ctx: ScanContext) -> bool:
    """Confirm the ``httpx`` on PATH is ProjectDiscovery's, not the Python library CLI.

    The Python ``httpx`` package ships its own console script named ``httpx``;
    feeding it ProjectDiscovery flags produces no usable output, so its bare
    presence must not select the JSONL probe path. ProjectDiscovery httpx is
    recognised by its version banner; anything else falls back to built-in
    probing.
    """
    result = await run_tool(["httpx", "-version"], RunOptions(timeout=15.0))
    if not result.ok:
        return False
    output = f"{result.stdout}\n{result.stderr}"
    if "projectdiscovery" in output.casefold():
        return True
    if re.search(r"httpx[^\n]{0,16}\s+\d", output, re.IGNORECASE):
        return False
    return True


async def _probe_with_pd_httpx(ctx: ScanContext, bus: EventBus, candidates: list[Host]) -> list[Host]:
    """Probe candidates through ProjectDiscovery httpx JSONL output."""
    argv = ["httpx", "-silent", "-json", "-status-code", "-title", "-tech-detect", "-cdn", "-ip", "-no-color"]
    stdin_text = "\n".join(c.host for c in candidates) + "\n"
    opts = RunOptions(timeout=float(ctx.config.timeout_for("httpx")), input_text=stdin_text)
    live: list[Host] = []
    total = len(candidates)
    async for line in stream_lines(argv, opts):
        host = _host_from_httpx_line(line)
        if host is None or not ctx.scope.in_scope(host.host):
            continue
        live.append(host)
        await bus.stage_progress(STAGE, len(live), total)
    return live


async def _probe_with_python_httpx(ctx: ScanContext, bus: EventBus, candidates: list[Host]) -> list[Host]:
    """Fallback: one GET per host via the python httpx library."""
    capped = candidates[:FALLBACK_HOST_CAP]
    await bus.log(
        f"PD httpx not installed; falling back to built-in probing ({len(capped)}/{len(candidates)} host(s)).",
        LogLevel.WARN,
    )
    limiter = RateLimiter(float(ctx.rate_limit))
    sem = asyncio.Semaphore(FALLBACK_CONCURRENCY)
    default_scheme = urlsplit(ctx.target_url).scheme or "https"
    results: list[Host] = []
    done = 0

    async with httpx.AsyncClient(follow_redirects=True, timeout=FALLBACK_TIMEOUT, verify=False) as client:

        async def probe(candidate: Host) -> None:
            nonlocal done
            await limiter.acquire()
            async with sem:
                result = await _single_probe(client, candidate, default_scheme)
            done += 1
            if result is not None and ctx.scope.in_scope(result.host):
                results.append(result)
            await bus.stage_progress(STAGE, done, len(capped))

        await asyncio.gather(*(probe(c) for c in capped), return_exceptions=True)
    return results


async def _single_probe(client: httpx.AsyncClient, candidate: Host, default_scheme: str) -> Host | None:
    """GET one candidate URL; return an enriched live Host or None on failure."""
    url = candidate.url or f"{default_scheme}://{candidate.host}"
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return None
    return Host(
        host=candidate.host,
        url=str(resp.url),
        status_code=resp.status_code,
        title=_extract_title(resp.text),
        server=resp.headers.get("server"),
        content_length=len(resp.content),
        scheme=resp.url.scheme,
        port=resp.url.port,
        is_live=True,
        source="httpx-fallback",
    )


def _host_from_httpx_line(line: str) -> Host | None:
    """Map one PD httpx JSONL record onto a live Host."""
    try:
        raw: object = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(raw, dict):
        return None
    url = raw.get("url")
    if not isinstance(url, str) or not url:
        return None
    parts = urlsplit(url)
    raw_host = raw.get("host")
    name = raw_host if isinstance(raw_host, str) and raw_host else (parts.hostname or "")
    if not name:
        return None
    tech_list = raw.get("tech")
    tech = [item for item in tech_list if isinstance(item, str)] if isinstance(tech_list, list) else []
    server_raw = raw.get("webserver") or raw.get("server")
    return Host(
        host=name,
        url=url,
        ip=_opt_str(raw.get("ip")),
        port=_opt_int(raw.get("port")) or parts.port,
        scheme=parts.scheme or _opt_str(raw.get("scheme")),
        status_code=_opt_int(raw.get("status_code")),
        title=_opt_str(raw.get("title")),
        server=server_raw if isinstance(server_raw, str) else None,
        content_length=_opt_int(raw.get("content_length")),
        tech=tech,
        cdn=isinstance(raw.get("cdn"), bool) and bool(raw.get("cdn")),
        is_live=True,
        source="httpx",
    )


def _opt_str(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _opt_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _extract_title(body: str) -> str | None:
    match = _TITLE_RE.search(body[:200_000])
    if match is None:
        return None
    title = html_lib.unescape(match.group(1)).strip()
    return title[:200] or None


def _bare_host(target: str) -> str:
    if target.startswith("["):
        end = target.find("]")
        return target[1:end] if end != -1 else target
    head, sep, tail = target.rpartition(":")
    if sep and tail.isdigit():
        return head
    return target


def _is_bare_ip(host: str) -> bool:
    return not any(ch.isascii() and ch.isalpha() for ch in host)


def _parse_host_port(line: str) -> tuple[str, int] | None:
    text = line.strip()
    if not text or text.count(":") != 1:
        return None
    host, _, port_text = text.partition(":")
    if not host or not port_text.isdigit():
        return None
    return host, int(port_text)


def _match_host(ctx: ScanContext, key: str) -> Host | None:
    direct = ctx.hosts.get(key)
    if direct is not None:
        return direct
    for host in ctx.hosts.values():
        if host.ip == key:
            return host
    return None
