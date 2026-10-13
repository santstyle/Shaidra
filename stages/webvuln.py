"""Web vulnerability scanning: nuclei templates, dalfox XSS, detection-only sqlmap.

nuclei runs its web-vuln template tags over the crawled (or live) URLs,
dalfox hunts XSS on parameterized URLs, and sqlmap only ever confirms a SQLi
that nuclei already hinted at — in strict detection-only mode, never dumping
data or writing to the target.
"""

from __future__ import annotations

import contextlib
import json
import re
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, JsonValue, LogLevel, ScanContext, Severity
from shaidra.utils.process import RunOptions, run_tool, stream_lines
from shaidra.utils.rate_limiter import RateLimiter

STAGE_NAME: Final[str] = "Web vulns"
MAX_INPUT: Final[int] = 500
MAX_DALFOX: Final[int] = 50
MAX_SQLMAP: Final[int] = 3
MAX_OWN_PROBES: Final[int] = 30
_OWN_TIMEOUT: Final[float] = 10.0
_REFLECTION_MARKER: Final[str] = "zzq<u>zz</u>"
_SQL_PAYLOADS: Final[tuple[str, ...]] = ("'", '"')
_SQL_ERROR_RE: Final[re.Pattern[str]] = re.compile(
    r"you have an error in your sql syntax|unclosed quotation mark|incorrect syntax near|"
    r"sqlstate|er_parse_error|sqlite.*error|mysql_(fetch|query|result)|"
    r"supplied argument is not a valid mysql|postgresql.*error|query failed.*postgres|"
    r"ora-\d{4,5}|microsoft odbc|microsoft jet|java\.sql\.sqlexception",
    re.IGNORECASE,
)
_NUCLEI_TAGS: Final[str] = "xss,sqli,ssrf,idor,lfi,rce,xxe"
_SCHEMES: Final[tuple[str, ...]] = ("http://", "https://")
_URL_RE: Final[re.Pattern[str]] = re.compile(r"https?://[^\s\"'<>]+")


@dataclass(frozen=True, slots=True)
class _Probe:
    """A parameterized URL whose value Shaidra replaces with test payloads."""

    url: str
    param: str


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Scan crawled URLs for web vulnerabilities and stream findings."""
    await bus.stage_start(STAGE_NAME)
    nuclei_ready = ctx.has_tool("nuclei")
    dalfox_ready = ctx.has_tool("dalfox")
    if not (nuclei_ready or dalfox_ready):
        await _builtin_fallback(ctx, bus)
        return
    urls = _input_urls(ctx)
    if not urls:
        await bus.stage_skip(STAGE_NAME, "no in-scope URLs to scan")
        return
    param_urls = [url for url in urls if "?" in url][:MAX_DALFOX]
    dalfox_planned = dalfox_ready and bool(param_urls)
    total = int(nuclei_ready) + int(dalfox_planned)
    done = 0
    temp_path: Path | None = None
    try:
        sqli_targets: list[str] = []
        if nuclei_ready:
            temp_path = _write_url_list(urls)
            if temp_path is None:
                await bus.log("nuclei: could not write the URL list file; skipping", LogLevel.WARN)
            else:
                sqli_targets = await _run_nuclei(ctx, bus, temp_path)
                done += 1
                await bus.stage_progress(STAGE_NAME, done, total)
        if dalfox_planned:
            await _run_dalfox(ctx, bus, param_urls)
            done += 1
            await bus.stage_progress(STAGE_NAME, done, total)
        if ctx.has_tool("sqlmap") and sqli_targets:
            await _run_sqlmap(ctx, bus, sqli_targets)
    finally:
        if temp_path is not None:
            with contextlib.suppress(OSError):
                temp_path.unlink()
    await bus.stage_done(STAGE_NAME, f"{len(urls)} URLs checked")


def _input_urls(ctx: ScanContext) -> list[str]:
    urls = _filter_urls(ctx, ctx.crawled_urls)
    if urls:
        return urls
    seeds = [ctx.target_url, *(host.url for host in ctx.live_hosts() if host.url)]
    return _filter_urls(ctx, seeds)


def _filter_urls(ctx: ScanContext, source: Sequence[str]) -> list[str]:
    urls: dict[str, None] = {}
    for candidate in source:
        clean = candidate.strip()
        if not clean.startswith(_SCHEMES):
            continue
        if not ctx.scope.in_scope(clean):
            continue
        urls[clean] = None
        if len(urls) >= MAX_INPUT:
            break
    return list(urls)


async def _builtin_fallback(ctx: ScanContext, bus: EventBus) -> None:
    """Run Shaidra's own probes when no external web scanner is installed.

    Non-destructive GET-only checks: reflected-input markers on parameterized
    URLs and error-based SQLi detection with a quote payload. Both are
    throttled through RateLimiter and capped by MAX_OWN_PROBES.
    """
    urls = _input_urls(ctx)
    if not urls:
        await bus.stage_skip(STAGE_NAME, "no in-scope URLs to scan")
        return
    if not ctx.web_reachable:
        await bus.stage_skip(STAGE_NAME, "nuclei and dalfox not installed and target not reachable")
        return
    probes = _own_probes(urls)
    if not probes:
        await bus.stage_skip(STAGE_NAME, "nuclei and dalfox not installed; no parameterized URLs to test")
        return
    await bus.log(
        f"nuclei and dalfox not installed; using built-in checks on {len(probes)} parameter(s)",
        LogLevel.WARN,
    )
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    found = 0
    async with httpx.AsyncClient(follow_redirects=False, timeout=_OWN_TIMEOUT) as client:
        found += await _own_reflection(ctx, bus, client, limiter, probes)
        found += await _own_sqli(ctx, bus, client, limiter, probes)
    await bus.stage_done(STAGE_NAME, f"{found} finding(s) from built-in probes")


def _own_probes(urls: Sequence[str]) -> list[_Probe]:
    """Pick up to MAX_OWN_PROBES unique (path, param) targets from the URLs."""
    probes: list[_Probe] = []
    seen: set[tuple[str, str]] = set()
    for url in urls:
        if len(probes) >= MAX_OWN_PROBES:
            break
        if "?" not in url:
            continue
        parts = urlsplit(url)
        for name, _ in parse_qsl(parts.query, keep_blank_values=True)[:2]:
            key = (parts.path, name.lower())
            if key in seen:
                continue
            seen.add(key)
            probes.append(_Probe(url=url, param=name))
    return probes


def _rebuild_url(url: str, param: str, value: str) -> str:
    """Return the URL with one query parameter replaced by ``value``."""
    parts = urlsplit(url)
    pairs = [(name, value if name == param else current) for name, current in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


async def _own_reflection(
    ctx: ScanContext, bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, probes: Sequence[_Probe]
) -> int:
    """Send a distinctive marker through every parameter and flag echoes."""
    found = 0
    for probe in probes:
        url = _rebuild_url(probe.url, probe.param, _REFLECTION_MARKER)
        await limiter.acquire()
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            continue
        if response.status_code != 200 or _REFLECTION_MARKER not in response.text:
            continue
        found += 1
        await bus.finding(
            Finding(
                title="Reflected input in query parameter",
                severity=Severity.LOW,
                category=Category.WEBVULN,
                host=_host_of(probe.url, ctx.target),
                tool="shaidra",
                url=probe.url,
                evidence=f"GET {url} echoed the {probe.param!r} marker in the response body",
                description=(
                    f"The {probe.param!r} query parameter echoes arbitrary input back into the page. "
                    "Unless the output is context-aware escaped, this enables reflected XSS and "
                    "content injection."
                ),
                raw={"param": probe.param, "marker": _REFLECTION_MARKER},
            )
        )
    return found


async def _own_sqli(
    ctx: ScanContext, bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, probes: Sequence[_Probe]
) -> int:
    """Append a quote to each parameter and flag database error patterns."""
    found = 0
    for probe in probes:
        for payload in _SQL_PAYLOADS:
            url = _rebuild_url(probe.url, probe.param, payload)
            await limiter.acquire()
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                continue
            if _SQL_ERROR_RE.search(response.text):
                found += 1
                await bus.finding(
                    Finding(
                        title="Error-based SQL injection (detection)",
                        severity=Severity.HIGH,
                        category=Category.WEBVULN,
                        host=_host_of(probe.url, ctx.target),
                        tool="shaidra",
                        url=url,
                        evidence=f"GET {url} produced a database error pattern in the response",
                        description=(
                            f"Appending {payload!r} to the {probe.param!r} parameter triggered an SQL "
                            "error message, indicating the value is embedded in a query without "
                            "sanitization. Confirm manually before exploitation."
                        ),
                        raw={"param": probe.param, "payload": payload},
                    )
                )
                break
    return found


def _write_url_list(urls: list[str]) -> Path | None:
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", prefix="shaidra-webvuln-", delete=False, encoding="utf-8", newline="\n"
        ) as handle:
            handle.write("\n".join(urls))
            handle.write("\n")
    except OSError:
        return None
    return Path(handle.name)


async def _run_nuclei(ctx: ScanContext, bus: EventBus, list_path: Path) -> list[str]:
    rate = str(ctx.config.lowered_rate() if ctx.waf else ctx.rate_limit)
    argv = ["nuclei", "-silent", "-jsonl", "-tags", _NUCLEI_TAGS, "-rate-limit", rate, "-l", str(list_path)]
    options = RunOptions(timeout=float(ctx.config.timeout_for("nuclei")))
    sqli_targets: list[str] = []
    found = 0
    async for line in stream_lines(argv, options):
        finding = _nuclei_finding(line, ctx.target)
        if finding is None:
            continue
        found += 1
        await bus.finding(finding)
        if finding.url is not None and _mentions_sql(finding) and finding.url not in sqli_targets:
            sqli_targets.append(finding.url)
    await bus.log(f"nuclei: {found} web vulnerability matches")
    return sqli_targets


def _nuclei_finding(line: str, fallback_host: str) -> Finding | None:
    payload = _load_object(line)
    if payload is None:
        return None
    info = payload.get("info")
    details: dict[str, JsonValue] = info if isinstance(info, dict) else {}
    template = _text(payload.get("templateID") or payload.get("template-id"))
    title = _text(details.get("name")) or template or "nuclei match"
    matched = _text(payload.get("matched-at")) or _text(payload.get("url")) or _text(payload.get("host"))
    url: str | None = matched or None
    classification = details.get("classification")
    cve = _first_str(classification.get("cve-id")) if isinstance(classification, dict) else None
    return Finding(
        title=title,
        severity=_severity(details.get("severity")),
        category=Category.WEBVULN,
        host=_host_of(url, fallback_host),
        tool="nuclei",
        evidence=_text(payload.get("curl-command")) or matched,
        url=url,
        description=_text(details.get("description")),
        reference=_first_str(details.get("reference")),
        cve=cve,
        template=template or None,
        raw=payload,
    )


async def _run_dalfox(ctx: ScanContext, bus: EventBus, urls: list[str]) -> None:
    options = RunOptions(timeout=float(ctx.config.timeout_for("dalfox")), input_text="\n".join(urls))
    found = 0
    async for line in stream_lines(["dalfox", "pipe", "--silence", "--no-color"], options):
        finding = _dalfox_finding(line, ctx.target)
        if finding is None:
            continue
        found += 1
        await bus.finding(finding)
    await bus.log(f"dalfox: {found} XSS matches across {len(urls)} parameterized URLs")


def _dalfox_finding(line: str, fallback_host: str) -> Finding | None:
    text = line.strip()
    if not text:
        return None
    head = text[:8].lower()
    if head.startswith("[v]") or head.startswith("[poc]"):
        url = _first_url(text)
        lowered = text.lower()
        severity = Severity.HIGH if ("high" in lowered or "critical" in lowered) else Severity.MEDIUM
    elif text.startswith("{"):
        payload = _load_object(text)
        if payload is None:
            return None
        url = _text(payload.get("url")) or _first_url(text)
        mapped = _severity(payload.get("severity"))
        severity = Severity.MEDIUM if mapped is Severity.UNKNOWN else mapped
    else:
        return None
    return Finding(
        title="Cross-site scripting (dalfox)",
        severity=severity,
        category=Category.WEBVULN,
        host=_host_of(url, fallback_host),
        tool="dalfox",
        evidence=text,
        url=url or None,
        description="dalfox reported a parameter that reflects an XSS payload.",
    )


async def _run_sqlmap(ctx: ScanContext, bus: EventBus, targets: list[str]) -> None:
    """Confirm at most MAX_SQLMAP nuclei-hinted URLs; detection only, no exfil."""
    options = RunOptions(timeout=float(ctx.config.timeout_for("sqlmap")))
    selected = targets[:MAX_SQLMAP]
    confirmed = 0
    for index, url in enumerate(selected, start=1):
        argv = ["sqlmap", "-u", url, "--batch", "--level=1", "--risk=1", "--smart"]
        result = await run_tool(argv, options)
        evidence = _vulnerable_line(result.stdout)
        if not evidence:
            continue
        confirmed += 1
        await bus.finding(
            Finding(
                title="SQL injection confirmed by sqlmap",
                severity=Severity.HIGH,
                category=Category.WEBVULN,
                host=_host_of(url, ctx.target),
                tool="sqlmap",
                evidence=evidence,
                url=url,
                description="Detection-only sqlmap probe (--batch --level=1 --risk=1 --smart) flagged the parameter.",
            )
        )
        await bus.stage_progress(STAGE_NAME, index, len(selected))
    await bus.log(f"sqlmap: {confirmed} confirmed SQL injection(s)")


def _vulnerable_line(stdout: str) -> str:
    for line in stdout.splitlines():
        if "is vulnerable" in line.lower():
            return line.strip()
    return ""


def _mentions_sql(finding: Finding) -> bool:
    return "sql" in f"{finding.template or ''} {finding.title}".lower()


def _severity(raw: JsonValue) -> Severity:
    text = raw.lower() if isinstance(raw, str) else ""
    match text:
        case "critical":
            return Severity.CRITICAL
        case "high":
            return Severity.HIGH
        case "medium":
            return Severity.MEDIUM
        case "low":
            return Severity.LOW
        case "info":
            return Severity.INFO
        case _:
            return Severity.UNKNOWN


def _load_object(line: str) -> dict[str, JsonValue] | None:
    try:
        payload: JsonValue = json.loads(line)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        return payload
    return None


def _text(value: JsonValue | None) -> str:
    return value if isinstance(value, str) else ""


def _first_str(value: JsonValue | None) -> str | None:
    if isinstance(value, str):
        return value or None
    if isinstance(value, list):
        for entry in value:
            if isinstance(entry, str) and entry:
                return entry
    return None


def _first_url(text: str) -> str:
    match = _URL_RE.search(text)
    return match.group(0) if match else ""


def _host_of(url: str, fallback: str) -> str:
    return urlsplit(url).hostname or fallback
