"""Web vulnerability scanning: nuclei templates, dalfox XSS, detection-only sqlmap.

nuclei runs its web-vuln template tags over the crawled (or live) URLs,
dalfox hunts XSS on parameterized URLs, and sqlmap only ever confirms a SQLi
that nuclei already hinted at — in strict detection-only mode, never dumping
data or writing to the target.
"""

from __future__ import annotations

import asyncio
import base64
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
from shaidra.utils.oob import InteractionServer
from shaidra.utils.process import RunOptions, run_tool, stream_lines
from shaidra.utils.rate_limiter import RateLimiter

STAGE_NAME: Final[str] = "Web vulns"
MAX_INPUT: Final[int] = 500
MAX_DALFOX: Final[int] = 50
MAX_SQLMAP: Final[int] = 3
MAX_OWN_PROBES: Final[int] = 120
MAX_XXE_URLS: Final[int] = 40
_MAX_CSRF: Final[int] = 25
_MAX_SSRF: Final[int] = 40
_OOB_WAIT: Final[float] = 2.5
_OWN_TIMEOUT: Final[float] = 10.0
_SSRF_PARAM_RE: Final[re.Pattern[str]] = re.compile(
    r"url|uri|link|site|host|domain|dest|target|redirect|next|return|path|"
    r"file|src|image|feed|proxy|callback|webhook|endpoint",
    re.IGNORECASE,
)
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
# Expected values are high-entropy products: a 5+ digit result is extremely
# unlikely to occur by chance in page markup or an embedded base64 blob, so a
# match reflects a real server-side evaluation rather than a coincidence.
_SSTI_PAYLOADS: Final[tuple[tuple[str, str], ...]] = (
    ("{{137*177}}", "24249"),
    ("${137*177}", "24249"),
    ("#{137*177}", "24249"),
    ("<%= 137*177 %>", "24249"),
    ("{{7*'7'}}", "7777777"),
)
_SSTI_DATA_URI_RE: Final[re.Pattern[str]] = re.compile(r"data:[^,;]*;base64,[A-Za-z0-9+/=]+", re.IGNORECASE)
_SSTI_B64_RUN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")
_XXE_PAYLOADS: Final[tuple[str, ...]] = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<root>&xxe;</root>",
    '<?xml version="1.0"?>'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>'
    "<root>&xxe;</root>",
)
_XXE_PARAM_RE: Final[re.Pattern[str]] = re.compile(r"xml|data|body|content|input|textarea|payload", re.IGNORECASE)
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
    injection, path traversal / LFI, server-side template injection, in-band
    XXE, and differential SQL injection, plus a static anti-CSRF token check on
    discovered forms. Every request is throttled through RateLimiter and the
    probe set is capped by MAX_OWN_PROBES.
    """
    urls = _input_urls(ctx)
    if not urls:
        await bus.stage_skip(STAGE_NAME, "no in-scope URLs to scan")
        return
    if not ctx.web_reachable:
        await bus.stage_skip(STAGE_NAME, "nuclei and dalfox not installed and target not reachable")
        return
    probes = _select_probes([*_query_probes(urls), *_form_probes(ctx.form_targets)])
    await bus.log(
        f"nuclei and dalfox not installed; using built-in checks on {len(probes)} parameter(s)",
        LogLevel.WARN,
    )
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    server = await _start_oob(ctx)
    found = 0
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=_OWN_TIMEOUT) as client:
            found += await _own_csrf(ctx, bus, ctx.form_targets)
            found += await _own_xxe(ctx, bus, client, limiter, urls, probes)
            if probes:
                if server is not None:
                    found += await _own_ssrf(ctx, bus, client, limiter, probes, server)
                found += await _own_reflection(ctx, bus, client, limiter, probes)
                found += await _own_cmdi(ctx, bus, client, limiter, probes)
                found += await _own_lfi(ctx, bus, client, limiter, probes)
                found += await _own_ssti(ctx, bus, client, limiter, probes)
                found += await _own_sqli(ctx, bus, client, limiter, probes)
    finally:
        if server is not None:
            await server.stop()
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


def _xxe_leaked(text: str) -> bool:
    """Report whether a response carried /etc/passwd contents (raw or base64)."""
    if _LFI_PASSWD_RE.search(text):
        return True
    for blob in _LFI_B64_RE.findall(text):
        with contextlib.suppress(ValueError):
            if b"root:" in base64.b64decode(blob):
                return True
    return False


async def _emit_xxe(ctx: ScanContext, bus: EventBus, url: str, source: str) -> None:
    """Raise one high-severity XXE finding for ``source``."""
    await bus.finding(
        Finding(
            title="XML external entity (XXE) injection",
            severity=Severity.HIGH,
            category=Category.WEBVULN,
            host=_host_of(url, ctx.target),
            tool="shaidra",
            url=url,
            evidence=f"{source} resolved an external entity and returned local file contents",
            description=(
                "The XML parser resolves external entities, letting an attacker read local "
                "files (e.g. /etc/passwd) or reach internal services — XML external entity "
                "(XXE) injection."
            ),
            raw={"source": source},
        )
    )


async def _own_xxe(
    ctx: ScanContext,
    bus: EventBus,
    client: httpx.AsyncClient,
    limiter: RateLimiter,
    urls: Sequence[str],
    probes: Sequence[_Probe],
) -> int:
    """POST XML external-entity payloads to discovered endpoints and flag file reads.

    Covers both endpoints that take a raw XML body (Content-Type application/xml)
    and forms that pass XML inside a field whose name looks XML-ish.
    """
    found = 0
    for probe in probes:
        if not _XXE_PARAM_RE.search(probe.param):
            continue
        response = await _probe_once(client, limiter, probe, _XXE_PAYLOADS[0])
        if response is not None and _xxe_leaked(response.text):
            found += 1
            await _emit_xxe(ctx, bus, probe.url, f"{probe.method} {probe.url} [{probe.param}]")
            break
    targets: list[str] = []
    seen: set[str] = set()
    for url in [*(probe.url for probe in probes), *urls]:
        if url in seen:
            continue
        seen.add(url)
        targets.append(url)
        if len(targets) >= MAX_XXE_URLS:
            break
    for url in targets:
        for payload in _XXE_PAYLOADS:
            await limiter.acquire()
            try:
                response = await client.post(
                    url,
                    content=payload,
                    headers={"Content-Type": "application/xml", "Accept": "*/*"},
                )
            except httpx.HTTPError:
                continue
            if _xxe_leaked(response.text):
                found += 1
                await _emit_xxe(ctx, bus, url, f"POST {url} (application/xml)")
                break
    return found


def _csrf_candidates(forms: Sequence[FormTarget]) -> list[FormTarget]:
    """State-changing POST forms that carry no obvious anti-CSRF token field."""
    selected: dict[tuple[str, str], FormTarget] = {}
    for form in forms:
        if form.method != "POST" or form.has_csrf_token or not form.fields:
            continue
        selected.setdefault((form.action_url, form.method), form)
    return list(selected.values())


async def _own_csrf(ctx: ScanContext, bus: EventBus, forms: Sequence[FormTarget]) -> int:
    """Report state-changing POST forms that submit without an anti-CSRF token.

    Emitted once per scan as a summary so a target with many tokenless forms
    does not flood the report; the individual actions are listed in the body.
    """
    candidates = _csrf_candidates(forms)
    if not candidates:
        return 0
    shown = candidates[:_MAX_CSRF]
    listing = "\n".join(f"- POST {form.action_url} (from {form.page_url})" for form in shown)
    if len(candidates) > len(shown):
        listing += f"\n- (+{len(candidates) - len(shown)} more)"
    await bus.finding(
        Finding(
            title="Missing anti-CSRF tokens on state-changing forms",
            severity=Severity.LOW,
            category=Category.WEBVULN,
            host=_host_of(shown[0].action_url, ctx.target),
            tool="shaidra",
            url=shown[0].action_url,
            evidence=f"{len(candidates)} POST form(s) submit without an anti-CSRF token",
            description=(
                "These forms submit state-changing POST requests without an anti-CSRF token. If the "
                "session is cookie-based, a cross-site request may trigger the action (CSRF). "
                "Confirm each manually:\n" + listing
            ),
            raw={"count": len(candidates), "forms": [form.to_dict() for form in shown]},
        )
    )
    return 1


def _loopback_host(host: str) -> bool:
    """Whether ``host`` names this machine (so a local callback listener is reachable)."""
    return host in {"127.0.0.1", "localhost", "::1", "0.0.0.0", ""}


async def _start_oob(ctx: ScanContext) -> InteractionServer | None:
    """Start the callback listener when an SSRF callback could actually return.

    A loopback listener is only reachable when the target runs locally; for a
    remote target, an ``oob_host`` (public forwarding host) must be configured.
    """
    host = urlsplit(ctx.target_url).hostname or ""
    if not (ctx.config.oob_host or _loopback_host(host)):
        return None
    server = InteractionServer()
    with contextlib.suppress(OSError):
        await server.start()
    return server if server.running else None


def _ssrf_candidates(probes: Sequence[_Probe]) -> list[_Probe]:
    """URL-ish parameters a server is most likely to fetch on our behalf."""
    selected: list[_Probe] = []
    seen: set[tuple[str, str, str]] = set()
    for probe in probes:
        if not _SSRF_PARAM_RE.search(probe.param):
            continue
        key = (probe.method, probe.url, probe.param.lower())
        if key in seen:
            continue
        seen.add(key)
        selected.append(probe)
        if len(selected) >= _MAX_SSRF:
            break
    return selected


async def _own_ssrf(
    ctx: ScanContext,
    bus: EventBus,
    client: httpx.AsyncClient,
    limiter: RateLimiter,
    probes: Sequence[_Probe],
    server: InteractionServer,
) -> int:
    """Inject callback URLs into URL-ish parameters and flag server-side fetches.

    Every request is sent first, then Shaidra waits once for callbacks, so the
    wait is paid a single time regardless of how many parameters were tested.
    """
    callback_host = ctx.config.oob_host or "127.0.0.1"
    pending: list[tuple[_Probe, str]] = []
    for probe in _ssrf_candidates(probes):
        token = server.new_token()
        response = await _probe_once(client, limiter, probe, server.callback_url(token, callback_host))
        if response is not None:
            pending.append((probe, token))
    if not pending:
        return 0
    await asyncio.sleep(_OOB_WAIT)
    found = 0
    for probe, token in pending:
        if not server.received(token):
            continue
        found += 1
        await bus.finding(
            Finding(
                title="Server-side request forgery (SSRF)",
                severity=Severity.HIGH,
                category=Category.WEBVULN,
                host=_host_of(probe.url, ctx.target),
                tool="shaidra",
                url=probe.url,
                evidence=(
                    f"{probe.method} {probe.url} [{probe.param}] made the server fetch "
                    f"{server.callback_url(token, callback_host)}"
                ),
                description=(
                    f"The {probe.param!r} parameter makes the server request an attacker-supplied "
                    "URL. A callback to Shaidra's listener proves outbound server-side request "
                    "forgery (SSRF), which can reach internal services or cloud metadata."
                ),
                raw={"param": probe.param, "method": probe.method, "token": token},
            )
        )
    return found


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


def _ssti_visible_text(text: str) -> str:
    """Strip embedded base64 blobs so random image data cannot fake a match.

    Pages frequently carry inline data-URI images whose base64 body is a long
    run of alphanumerics. A short expected value can appear inside that run by
    chance (and the blob is regenerated per request, so the baseline does not
    exclude it), so the comparison runs on markup with those blobs removed.
    """
    return _SSTI_B64_RUN_RE.sub(" ", _SSTI_DATA_URI_RE.sub(" ", text))


async def _own_ssti(
    ctx: ScanContext, bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, probes: Sequence[_Probe]
) -> int:
    """Send template expressions and flag arithmetic that the server evaluated."""
    found = 0
    for probe in probes:
        baseline = await _probe_once(client, limiter, probe, _benign_value(probe))
        baseline_text = _ssti_visible_text(baseline.text) if baseline is not None else ""
        for payload, expected in _SSTI_PAYLOADS:
            response = await _probe_once(client, limiter, probe, payload)
            if response is None:
                continue
            if expected in _ssti_visible_text(response.text) and expected not in baseline_text:
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
