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
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, FormTarget, JsonValue, LogLevel, ScanContext, Severity
from shaidra.utils.process import RunOptions, run_tool, stream_lines
from shaidra.utils.rate_limiter import RateLimiter

STAGE_NAME: Final[str] = "Web vulns"
MAX_INPUT: Final[int] = 500
MAX_DALFOX: Final[int] = 50
MAX_SQLMAP: Final[int] = 3
MAX_OWN_PROBES: Final[int] = 120
_OWN_TIMEOUT: Final[float] = 10.0
_REFLECTION_MARKER: Final[str] = "sdrq<u>z9</u>k"
_REFLECTION_TEXT: Final[str] = "sdrq"
_CMDI_MARKER: Final[str] = "SDRm9kXq7"
_CMDI_LITERAL: Final[str] = f"{_CMDI_MARKER[:6]}$(){_CMDI_MARKER[6:]}"
_CMDI_TEMPLATES: Final[tuple[str, ...]] = (
    f";echo {_CMDI_LITERAL}",
    f"|echo {_CMDI_LITERAL}",
    f"&echo {_CMDI_LITERAL}",
    f"$(echo {_CMDI_LITERAL})",
    f"%0aecho {_CMDI_LITERAL}",
)
_LFI_PAYLOADS: Final[tuple[str, ...]] = (
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
)
_LFI_PASSWD_RE: Final[re.Pattern[str]] = re.compile(r"root:[^:\n]*:0:0:")
_LFI_B64_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
_SSTI_PAYLOADS: Final[tuple[tuple[str, str], ...]] = (
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
)
_SQL_PAYLOADS: Final[tuple[str, ...]] = ("'", '"')
_SQL_CONTROL: Final[str] = "zqz9"
_SQL_DIFF_RATIO: Final[float] = 0.03
_SQL_MIN_DELTA: Final[int] = 16
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
    """A request whose one parameter Shaidra replaces with test payloads.

    ``method`` is ``GET`` (values ride the query string) or ``POST`` (values
    ride the form body). ``fields`` holds the other parameters so the request
    stays well-formed; only ``param`` is swapped for each payload.
    """

    method: str
    url: str
    param: str
    fields: dict[str, str]


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

    Non-destructive, read-only checks against every discovered parameter —
    query strings and form fields alike, GET or POST: reflected XSS, OS command
    injection, path traversal / LFI, server-side template injection, and
    differential SQL injection. Every request is throttled through RateLimiter
    and the probe set is capped by MAX_OWN_PROBES.
    """
    urls = _input_urls(ctx)
    if not urls:
        await bus.stage_skip(STAGE_NAME, "no in-scope URLs to scan")
        return
    if not ctx.web_reachable:
        await bus.stage_skip(STAGE_NAME, "nuclei and dalfox not installed and target not reachable")
        return
    probes = _select_probes([*_query_probes(urls), *_form_probes(ctx.form_targets)])
    if not probes:
        await bus.stage_skip(STAGE_NAME, "nuclei and dalfox not installed; no parameters to test")
        return
    await bus.log(
        f"nuclei and dalfox not installed; using built-in checks on {len(probes)} parameter(s)",
        LogLevel.WARN,
    )
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    found = 0
    async with httpx.AsyncClient(follow_redirects=False, timeout=_OWN_TIMEOUT) as client:
        found += await _own_reflection(ctx, bus, client, limiter, probes)
        found += await _own_cmdi(ctx, bus, client, limiter, probes)
        found += await _own_lfi(ctx, bus, client, limiter, probes)
        found += await _own_ssti(ctx, bus, client, limiter, probes)
        found += await _own_sqli(ctx, bus, client, limiter, probes)
    await bus.stage_done(STAGE_NAME, f"{found} finding(s) from built-in probes")


def _query_probes(urls: Sequence[str]) -> list[_Probe]:
    """Build GET probes from the query parameters of the discovered URLs."""
    probes: list[_Probe] = []
    seen: set[tuple[str, str]] = set()
    for url in urls:
        if "?" not in url:
            continue
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if not pairs:
            continue
        base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
        fields = dict(pairs)
        for name, _ in pairs[:2]:
            key = (base, name.lower())
            if key in seen:
                continue
            seen.add(key)
            probes.append(_Probe(method="GET", url=base, param=name, fields=dict(fields)))
    return probes


def _form_probes(forms: Sequence[FormTarget]) -> list[_Probe]:
    """Build GET/POST probes from the fields of the discovered HTML forms."""
    probes: list[_Probe] = []
    seen: set[tuple[str, str, str]] = set()
    for form in forms:
        for name in form.fields:
            key = (form.action_url, form.method, name.lower())
            if key in seen:
                continue
            seen.add(key)
            probes.append(_Probe(method=form.method, url=form.action_url, param=name, fields=dict(form.fields)))
    return probes


def _select_probes(probes: Sequence[_Probe]) -> list[_Probe]:
    """Deduplicate by (method, url, param), keeping the richest field set, then cap.

    A form and its GET query-string URL can yield the same target; the form
    carries the sibling fields the endpoint needs, so it must win over the
    query-only probe rather than be discarded.
    """
    selected: list[_Probe] = []
    index: dict[tuple[str, str, str], int] = {}
    for probe in probes:
        key = (probe.method, probe.url, probe.param.lower())
        at = index.get(key)
        if at is not None:
            if len(probe.fields) > len(selected[at].fields):
                selected[at] = probe
            continue
        index[key] = len(selected)
        selected.append(probe)
        if len(selected) >= MAX_OWN_PROBES:
            break
    return selected


def _benign_value(probe: _Probe) -> str:
    """Return the probe's current value, or ``1`` when it was blank."""
    value = probe.fields.get(probe.param, "").strip()
    return value or "1"


async def _probe_once(
    client: httpx.AsyncClient, limiter: RateLimiter, probe: _Probe, value: str
) -> httpx.Response | None:
    """Send one throttled request with ``probe.param`` replaced by ``value``."""
    fields = dict(probe.fields)
    fields[probe.param] = value
    await limiter.acquire()
    try:
        if probe.method == "POST":
            return await client.post(probe.url, data=fields)
        return await client.get(probe.url, params=fields)
    except httpx.HTTPError:
        return None


def _deviates(actual: int, expected: int) -> bool:
    """Report whether a body length strays from ``expected`` beyond tolerance.

    The tolerance is a percentage of the expected length with an absolute floor
    so tiny pages are not tripped by a single-character change.
    """
    return abs(actual - expected) > max(int(expected * _SQL_DIFF_RATIO), _SQL_MIN_DELTA)


async def _own_reflection(
    ctx: ScanContext, bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, probes: Sequence[_Probe]
) -> int:
    """Send an HTML marker through every parameter and flag unescaped echoes."""
    found = 0
    for probe in probes:
        response = await _probe_once(client, limiter, probe, _REFLECTION_MARKER)
        if response is None or response.status_code != 200:
            continue
        text = response.text
        if _REFLECTION_MARKER in text:
            severity, note = Severity.HIGH, "the raw HTML marker is echoed unescaped"
        elif _REFLECTION_TEXT in text:
            severity, note = Severity.LOW, "the marker text is echoed but the HTML tags were stripped or escaped"
        else:
            continue
        found += 1
        await bus.finding(
            Finding(
                title="Reflected cross-site scripting" if severity is Severity.HIGH else "Reflected input",
                severity=severity,
                category=Category.WEBVULN,
                host=_host_of(probe.url, ctx.target),
                tool="shaidra",
                url=probe.url,
                evidence=f"{probe.method} {probe.url} echoed the {probe.param!r} marker in the response body",
                description=(
                    f"The {probe.param!r} parameter reflects arbitrary input into the page; {note}. "
                    "This enables reflected XSS and content injection unless the context is escaped."
                ),
                raw={"param": probe.param, "method": probe.method, "marker": _REFLECTION_MARKER},
            )
        )
    return found


async def _own_cmdi(
    ctx: ScanContext, bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, probes: Sequence[_Probe]
) -> int:
    """Try shell metacharacter payloads whose echoed marker proves execution."""
    found = 0
    for probe in probes:
        for payload in _CMDI_TEMPLATES:
            response = await _probe_once(client, limiter, probe, payload)
            if response is None or _CMDI_MARKER not in response.text:
                continue
            found += 1
            await bus.finding(
                Finding(
                    title="OS command injection",
                    severity=Severity.HIGH,
                    category=Category.WEBVULN,
                    host=_host_of(probe.url, ctx.target),
                    tool="shaidra",
                    url=probe.url,
                    evidence=f"{probe.method} {probe.url} [{probe.param}] returned the executed marker {_CMDI_MARKER!r}",
                    description=(
                        f"The {probe.param!r} parameter is passed to a shell: a metacharacter payload "
                        "executed a command whose output appears in the response (OS command injection)."
                    ),
                    raw={"param": probe.param, "method": probe.method, "payload": payload},
                )
            )
            break
    return found


async def _own_lfi(
    ctx: ScanContext, bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, probes: Sequence[_Probe]
) -> int:
    """Probe for path traversal and local file inclusion with file-read payloads."""
    found = 0
    for probe in probes:
        baseline = await _probe_once(client, limiter, probe, _benign_value(probe))
        baseline_text = baseline.text if baseline is not None else ""
        for payload in _LFI_PAYLOADS:
            response = await _probe_once(client, limiter, probe, payload)
            if response is None:
                continue
            text = response.text
            passwd = _LFI_PASSWD_RE.search(text)
            b64 = _LFI_B64_RE.search(text) and not _LFI_B64_RE.search(baseline_text)
            if not (passwd or b64):
                continue
            found += 1
            await bus.finding(
                Finding(
                    title="Path traversal / local file inclusion",
                    severity=Severity.HIGH,
                    category=Category.WEBVULN,
                    host=_host_of(probe.url, ctx.target),
                    tool="shaidra",
                    url=probe.url,
                    evidence=f"{probe.method} {probe.url} [{probe.param}={payload}] returned local file contents",
                    description=(
                        f"The {probe.param!r} parameter accepts a file path, letting an attacker read "
                        "arbitrary local files (e.g. /etc/passwd) — path traversal / LFI."
                    ),
                    raw={"param": probe.param, "method": probe.method, "payload": payload},
                )
            )
            break
    return found


async def _own_ssti(
    ctx: ScanContext, bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, probes: Sequence[_Probe]
) -> int:
    """Send template expressions and flag arithmetic that the server evaluated."""
    found = 0
    for probe in probes:
        baseline = await _probe_once(client, limiter, probe, _benign_value(probe))
        baseline_text = baseline.text if baseline is not None else ""
        for payload, expected in _SSTI_PAYLOADS:
            response = await _probe_once(client, limiter, probe, payload)
            if response is None:
                continue
            if expected in response.text and expected not in baseline_text:
                found += 1
                await bus.finding(
                    Finding(
                        title="Server-side template injection",
                        severity=Severity.HIGH,
                        category=Category.WEBVULN,
                        host=_host_of(probe.url, ctx.target),
                        tool="shaidra",
                        url=probe.url,
                        evidence=f"{probe.method} {probe.url} [{probe.param}={payload}] evaluated to {expected}",
                        description=(
                            f"The {probe.param!r} parameter is rendered through a template engine: the "
                            f"expression {payload!r} evaluated server-side to {expected!r} (SSTI)."
                        ),
                        raw={"param": probe.param, "method": probe.method, "payload": payload, "expected": expected},
                    )
                )
                break
    return found


async def _own_sqli(
    ctx: ScanContext, bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, probes: Sequence[_Probe]
) -> int:
    """Flag SQL error patterns, and quotes that break a response beyond its own drift.

    A stateful endpoint can grow on every request (for example a page that
    appends a row), which would fake a length difference. Two identical benign
    requests establish the per-request drift, and each payload must deviate
    from that drift before it counts as a differential.
    """
    found = 0
    for probe in probes:
        original = _benign_value(probe)
        first = await _probe_once(client, limiter, probe, original)
        second = await _probe_once(client, limiter, probe, original)
        if first is None or second is None:
            continue
        drift = len(second.text) - len(first.text)
        control = await _probe_once(client, limiter, probe, original + _SQL_CONTROL)
        if control is None:
            continue
        stable = (
            first.status_code == 200
            and second.status_code == 200
            and control.status_code == 200
            and not _deviates(len(control.text), len(second.text) + drift)
        )
        for payload in _SQL_PAYLOADS:
            response = await _probe_once(client, limiter, probe, original + payload)
            if response is None:
                continue
            error_hit = bool(_SQL_ERROR_RE.search(response.text))
            differential = (
                not error_hit
                and stable
                and response.status_code == 200
                and _deviates(len(response.text), len(control.text) + drift)
            )
            if not (error_hit or differential):
                continue
            found += 1
            outcome = (
                "produced a database error pattern"
                if error_hit
                else "changed the response beyond the endpoint's own drift"
            )
            await bus.finding(
                Finding(
                    title="SQL injection",
                    severity=Severity.HIGH,
                    category=Category.WEBVULN,
                    host=_host_of(probe.url, ctx.target),
                    tool="shaidra",
                    url=probe.url,
                    evidence=f"{probe.method} {probe.url} [{probe.param}={original + payload}] {outcome}",
                    description=(
                        f"A {payload!r} quote in the {probe.param!r} parameter alters the query result, "
                        "indicating the value reaches SQL without sanitization. Confirm manually."
                    ),
                    raw={"param": probe.param, "method": probe.method, "payload": payload, "differential": differential},
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
