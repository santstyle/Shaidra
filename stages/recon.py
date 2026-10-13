"""Stage 1: subdomain enumeration and live-host probing.

`run` discovers candidate hosts (subfinder/assetfinder, or a single seeded
host for bare-IP targets) and confirms liveness with ProjectDiscovery httpx,
falling back to Shaidra's own httpx library when the Go tool is missing.
`scan_ports` runs naabu against the target and reports admin/database ports.
"""

from __future__ import annotations

import asyncio
import contextlib
import html as html_lib
import json
import re
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, Host, LogLevel, ScanContext, Severity
from shaidra.utils.process import RunOptions, run_tool, stream_lines
from shaidra.utils.http import make_http_client
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
_PORT_SCAN_TIMEOUT: Final[float] = 1.5
_PORT_SCAN_CONCURRENCY: Final[int] = 200
_COMMON_PORTS: Final[tuple[int, ...]] = (
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    465, 514, 587, 631, 636, 993, 995, 1080, 1433, 1521, 1723, 2049, 2082,
    2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 3000, 3128, 3268,
    3306, 3389, 3690, 4000, 4040, 4369, 4444, 4848, 5000, 5432, 5555, 5601,
    5672, 5900, 5901, 5984, 6000, 6379, 6443, 7001, 7002, 7077, 7443, 8000,
    8008, 8009, 8010, 8042, 8069, 8080, 8081, 8086, 8088, 8090, 8161, 8180,
    8200, 8443, 8500, 8529, 8888, 8983, 9000, 9001, 9042, 9060, 9090, 9092,
    9100, 9160, 9200, 9300, 9443, 10000, 10250, 11211, 15672, 27017, 27018,
    50000, 50070,
)
_CRT_SH_URL: Final[str] = "https://crt.sh/"
_HACKERTARGET_URL: Final[str] = "https://api.hackertarget.com/hostsearch/"
_CRT_TIMEOUT: Final[float] = 25.0
_DNS_TIMEOUT: Final[float] = 5.0
_BUILTIN_ENUM_CONCURRENCY: Final[int] = 30
_WILDCARD_PROBE_LABEL: Final[str] = "shaidra-wildcard-probe-9f3a1c"


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
    """Scan common ports and report interesting open services."""
    if ctx.has_tool("naabu"):
        await _scan_ports_naabu(ctx, bus)
        return
    await _scan_ports_builtin(ctx, bus)


async def _scan_ports_naabu(ctx: ScanContext, bus: EventBus) -> None:
    """Top-ports scan via ProjectDiscovery naabu."""
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


async def _scan_ports_builtin(ctx: ScanContext, bus: EventBus) -> None:
    """Fallback: async TCP connect scan over a common-port list.

    Used when naabu is unavailable — including when a host antivirus
    quarantines the naabu binary — so port discovery still works out of the box.
    """
    await bus.stage_start(PORT_STAGE)
    host = _bare_host(ctx.target)
    matched = _match_host(ctx, host)
    if matched is None:
        await bus.stage_skip(PORT_STAGE, "target not in scope")
        return
    await bus.log(
        f"naabu not installed; falling back to built-in TCP scan ({len(_COMMON_PORTS)} common ports).",
        LogLevel.WARN,
    )
    limiter = RateLimiter(float(ctx.rate_limit))
    sem = asyncio.Semaphore(_PORT_SCAN_CONCURRENCY)
    open_ports: list[int] = []

    async def probe(port: int) -> None:
        await limiter.acquire()
        async with sem:
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=_PORT_SCAN_TIMEOUT)
            except (OSError, asyncio.TimeoutError):
                return
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        open_ports.append(port)

    await asyncio.gather(*(probe(port) for port in _COMMON_PORTS), return_exceptions=True)
    open_ports.sort()
    if matched.port is None and open_ports:
        matched.port = open_ports[0]
    for port in open_ports:
        service = _ADMIN_PORTS.get(port)
        if service is None:
            continue
        await bus.finding(
            Finding(
                title=f"Open {service} port {port}",
                severity=Severity.INFO,
                category=Category.RECON,
                host=matched.host,
                tool="builtin",
                evidence=f"{host}:{port}",
                url=matched.url,
                description=f"Port {port} ({service}) is reachable on {host}.",
            )
        )
    await bus.stage_done(PORT_STAGE, f"{len(open_ports)} open port(s) found")


async def _enumerate_subdomains(ctx: ScanContext, bus: EventBus, base: str) -> list[str]:
    """Run the installed enum tools and return sorted, in-scope hostnames."""
    argvs: list[list[str]] = []
    if ctx.has_tool("subfinder"):
        argvs.append(["subfinder", "-d", base, "-silent"])
    if ctx.has_tool("assetfinder"):
        argvs.append(["assetfinder", "--subs-only", base])
    if argvs:
        results = await asyncio.gather(*(run_tool(argv, RunOptions(timeout=_tool_timeout(ctx, argv[0]))) for argv in argvs))
        merged: set[str] = set()
        for result in results:
            if not result.ok:
                await bus.log(f"{result.tool} failed (rc={result.returncode}): {result.stderr.strip()}", LogLevel.WARN)
                continue
            merged.update(line.strip() for line in result.stdout.splitlines() if line.strip())
    else:
        merged = await _enumerate_builtin(ctx, bus, base)
    scoped = sorted(name for name in merged if ctx.scope.in_scope(name))
    await bus.log(f"Subdomain enumeration found {len(scoped)} in-scope candidate(s).")
    return scoped


async def _enumerate_builtin(ctx: ScanContext, bus: EventBus, base: str) -> set[str]:
    """Built-in subdomain discovery: Certificate Transparency logs + DNS brute force.

    Used only when subfinder/assetfinder are absent so a bare hostname still
    yields subdomains. CT-log names come from a third party (crt.sh) and are
    fetched with a bare client so no target auth headers leak; the DNS
    brute-force is skipped when the domain answers wildcard DNS, since every
    label would then falsely "resolve".
    """
    await bus.log(
        "No subdomain enumeration tool installed; using built-in enumeration (Certificate Transparency + DNS wordlist).",
        LogLevel.WARN,
    )
    found: set[str] = set()
    found.update(await _crt_sh_names(base))
    found.update(await _hackertarget_names(base))
    if await _has_wildcard_dns(base):
        await bus.log(
            f"{base} answers a random label (wildcard DNS); DNS brute-force skipped to avoid false positives.",
            LogLevel.WARN,
        )
    else:
        found.update(await _dns_brute(base, ctx.config.wordlist_subdomains))
    return found


async def _crt_sh_names(base: str) -> set[str]:
    """Return hostnames under `base` from Certificate Transparency logs."""
    names: set[str] = set()
    bare = base.casefold()
    try:
        async with httpx.AsyncClient(timeout=_CRT_TIMEOUT, headers={"User-Agent": "shaidra"}) as client:
            resp = await client.get(_CRT_SH_URL, params={"q": f"%.{base}", "output": "json"})
            if resp.status_code != 200:
                return names
            raw = resp.json()
    except (httpx.HTTPError, ValueError):
        return names
    if not isinstance(raw, list):
        return names
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        value = entry.get("name_value")
        if not isinstance(value, str):
            continue
        for line in value.splitlines():
            name = line.strip().lstrip("*.").casefold()
            if name == bare or name.endswith("." + bare):
                names.add(name)
    return names


async def _hackertarget_names(base: str) -> set[str]:
    """Return hostnames under `base` from the hackertarget host-search API."""
    names: set[str] = set()
    bare = base.casefold()
    try:
        async with httpx.AsyncClient(timeout=_CRT_TIMEOUT, headers={"User-Agent": "shaidra"}) as client:
            resp = await client.get(_HACKERTARGET_URL, params={"q": base})
            if resp.status_code != 200:
                return names
            body = resp.text
    except httpx.HTTPError:
        return names
    for line in body.splitlines():
        name = line.split(",", 1)[0].strip().casefold()
        if name and (name == bare or name.endswith("." + bare)):
            names.add(name)
    return names


async def _dns_brute(base: str, configured: str) -> set[str]:
    """Resolve each wordlist label under `base`; return the names that resolve."""
    words = _load_subdomain_labels(configured)
    if not words:
        return set()
    sem = asyncio.Semaphore(_BUILTIN_ENUM_CONCURRENCY)
    found: set[str] = set()

    async def check(word: str) -> None:
        name = f"{word}.{base}"
        async with sem:
            if await _resolves(name):
                found.add(name)

    await asyncio.gather(*(check(word) for word in words), return_exceptions=True)
    return found


async def _has_wildcard_dns(base: str) -> bool:
    """Return True when a random label under `base` resolves (wildcard DNS)."""
    return await _resolves(f"{_WILDCARD_PROBE_LABEL}.{base}")


async def _resolves(name: str) -> bool:
    """Return True when `name` resolves to at least one address."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(name, None), timeout=_DNS_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        return False
    return bool(infos)


def _load_subdomain_labels(configured: str) -> list[str]:
    """Read subdomain labels from the first existing wordlist, or return []."""
    path = _resolve_subdomain_wordlist(configured)
    if path is None:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def _resolve_subdomain_wordlist(configured: str) -> Path | None:
    """Return the first existing subdomain wordlist, or None when none exist."""
    requested = Path(configured)
    package_root = Path(__file__).resolve().parent.parent
    if requested.is_absolute():
        candidates = [requested]
    else:
        candidates = [
            Path.cwd() / requested,
            package_root / requested,
            package_root / "wordlists" / requested.name,
        ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


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

    async with make_http_client(ctx, follow_redirects=True, timeout=FALLBACK_TIMEOUT, verify=False) as client:

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
    """GET one candidate URL; return an enriched live Host or None on failure.

    A discovered subdomain carries only its name, so it is tried with the
    target's scheme first and then the opposite one — a host that serves only
    plain HTTP (or only HTTPS) would otherwise be written off as dead.
    """
    if candidate.url:
        urls = [candidate.url]
    else:
        alternate = "http" if default_scheme == "https" else "https"
        urls = [f"{default_scheme}://{candidate.host}", f"{alternate}://{candidate.host}"]
    for url in urls:
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            continue
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
    return None


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
