"""Content discovery: find sensitive paths exposed by the target web server.

Prefers feroxbuster, falls back to ffuf, and skips cleanly when neither tool
or a usable wordlist is available. Paths classified as sensitive produce a
"path exposed" finding, and every fetched response body is also scanned for
leaked credentials, API keys, and PII — so a file whose *contents* leak
secrets is reported even when its name looks innocuous.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, Host, JsonValue, LogLevel, ScanContext, Severity
from shaidra.utils.process import RunOptions, run_tool, stream_lines
from shaidra.utils.http import make_http_client
from shaidra.utils.rate_limiter import RateLimiter
from shaidra.utils.secrets import SecretMatch, scan_text
from shaidra.stages.misconfig import is_known_exposure

STAGE_NAME: Final[str] = "Content discovery"
_STATUS_CODES: Final[str] = "200,204,301,302,307,401,403"
_MAX_HITS: Final[int] = 500
_MAX_FINDINGS: Final[int] = 40
_MAX_BASES: Final[int] = 6
_PROGRESS_EVERY: Final[int] = 25
_OWN_BUDGET: Final[int] = 400
_OWN_TIMEOUT: Final[float] = 10.0
_OWN_HIT_CODES: Final[frozenset[int]] = frozenset({200, 204, 301, 302, 307, 401, 403})
_BODY_CAP: Final[int] = 256_000
_BODY_FETCH_BUDGET: Final[int] = 150
_TEXT_TYPES: Final[tuple[str, ...]] = (
    "json", "text", "xml", "javascript", "html", "yaml", "csv", "x-www-form-urlencoded",
)

# Sensitivity map, matched against the lowercased path. First tier that
# matches wins, so the most dangerous tier is checked first.
_HIGH_MARKERS: Final[tuple[str, ...]] = (
    ".git/", ".env", "wp-config", "backup", ".sql", ".bak", "config", "credential",
)
_MEDIUM_MARKERS: Final[tuple[str, ...]] = (
    "admin", "phpmyadmin", "server-status", ".htaccess", ".ds_store",
)
_LOW_MARKERS: Final[tuple[str, ...]] = (
    ".htpasswd", ".gitignore", "phpinfo", "info.php", "actuator", "server-info",
    "metrics", "debug", "swagger", "graphiql", "graphql", "console", "setup",
    "install", "trace", "dump", ".aws/", "wp-json", "wp-login",
)


@dataclass(slots=True)
class _Hit:
    url: str
    status: int
    length: int
    tool: str
    body: str = ""
    ctype: str = ""


@dataclass(slots=True)
class _Baseline:
    """The server's response to a guaranteed-missing path (its catch-all)."""

    status: int
    body: str
    ctype: str


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Enumerate sensitive content paths on every live in-scope host."""
    await bus.stage_start(STAGE_NAME)
    if not ctx.scope.in_scope(ctx.target_url):
        await bus.stage_skip(STAGE_NAME, "target out of scope")
        return
    wordlist = _resolve_wordlist(ctx.config.wordlist_content)
    if wordlist is None:
        await bus.stage_skip(STAGE_NAME, f"content wordlist not found: {ctx.config.wordlist_content}")
        return
    bases = _probe_bases(ctx)
    hits: list[_Hit] = []
    if ctx.has_tool("feroxbuster"):
        for base in bases:
            hits.extend(await _feroxbuster_hits(ctx, base, wordlist, bus))
    elif ctx.has_tool("ffuf"):
        for base in bases:
            hits.extend(await _ffuf_hits(ctx, base, wordlist))
    elif ctx.web_reachable:
        await bus.log("feroxbuster and ffuf not installed; using built-in wordlist probing", LogLevel.WARN)
        for base in bases:
            hits.extend(await _own_hits(ctx, base, wordlist, bus))
    else:
        await bus.stage_skip(STAGE_NAME, "feroxbuster and ffuf not installed and target not reachable")
        return
    await _enrich_bodies(ctx, bus, hits)
    baselines = await _baselines(ctx, bases)
    emitted = await _emit_findings(ctx, bus, hits, baselines)
    await bus.stage_done(STAGE_NAME, f"{emitted} sensitive paths from {len(hits)} responses")


def _probe_bases(ctx: ScanContext) -> list[str]:
    """Return one base URL per live in-scope host so subdomains are covered too."""
    bases: list[str] = []
    for host in ctx.live_hosts():
        if not ctx.scope.in_scope(host.host):
            continue
        base = _host_base(host)
        if base not in bases:
            bases.append(base)
        if len(bases) >= _MAX_BASES:
            break
    if not bases and ctx.scope.in_scope(ctx.target_url):
        bases.append(ctx.target_url.rstrip("/"))
    return bases


def _host_base(host: Host) -> str:
    if host.url is not None:
        return host.url.rstrip("/")
    netloc = host.host if host.port in (None, 80, 443) else f"{host.host}:{host.port}"
    return f"{host.scheme or 'https'}://{netloc}"


def _resolve_wordlist(configured: str) -> Path | None:
    """Return the first existing content wordlist, or None when none exist."""
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
    candidates.append(package_root / "wordlists" / "common.txt")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


async def _feroxbuster_hits(ctx: ScanContext, base: str, wordlist: Path, bus: EventBus) -> list[_Hit]:
    argv = [
        "feroxbuster", "-u", base, "--json", "-w", str(wordlist),
        "-t", str(ctx.config.ffuf_threads), "-s", _STATUS_CODES, "--silent",
    ]
    options = RunOptions(timeout=ctx.config.timeout_for("feroxbuster"))
    total = _wordlist_entries(wordlist)
    hits: list[_Hit] = []
    seen = 0
    async for line in stream_lines(argv, options):
        seen += 1
        if seen % _PROGRESS_EVERY == 0:
            await bus.stage_progress(STAGE_NAME, seen, total)
        if len(hits) >= _MAX_HITS:
            break
        hit = _ferox_line(line)
        if hit is not None:
            hits.append(hit)
    return hits


async def _ffuf_hits(ctx: ScanContext, base: str, wordlist: Path) -> list[_Hit]:
    """Run ffuf against one base, reading its JSON report from a temp file.

    ffuf's ``-o -`` (write to stdout) does not work on Windows — it creates a
    file named ``-`` in the working directory and leaves stdout empty — so the
    report always goes to a temp file and is read back from there.
    """
    handle, report = tempfile.mkstemp(prefix="shaidra-ffuf-", suffix=".json")
    os.close(handle)
    try:
        argv = [
            "ffuf", "-u", f"{base.rstrip('/')}/FUZZ", "-w", str(wordlist),
            "-mc", _STATUS_CODES, "-of", "json", "-o", report, "-s",
        ]
        options = RunOptions(timeout=ctx.config.timeout_for("ffuf"))
        result = await run_tool(argv, options)
        text = _read_report(report) or result.stdout
        return _ffuf_stdout(text)
    finally:
        try:
            os.remove(report)
        except OSError:
            pass


def _read_report(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


async def _own_hits(ctx: ScanContext, base: str, wordlist: Path, bus: EventBus) -> list[_Hit]:
    """Budget-limited probing of the content wordlist with Shaidra's own httpx.

    Used when neither feroxbuster nor ffuf is installed: every wordlist entry
    is requested once, throttled through RateLimiter, and status codes that
    warrant review are kept for the shared sensitivity classifier. Request
    count is capped by _OWN_BUDGET.
    """
    lines = _wordlist_lines(wordlist)
    budget = min(len(lines), _OWN_BUDGET)
    if budget == 0:
        return []
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    hits: list[_Hit] = []
    base = base.rstrip("/")
    async with make_http_client(ctx, follow_redirects=False, timeout=_OWN_TIMEOUT) as client:
        for index in range(budget):
            if len(hits) >= _MAX_HITS:
                break
            await bus.stage_progress(STAGE_NAME, index + 1, budget)
            path = lines[index].strip()
            if not path or path.startswith("#"):
                continue
            url = f"{base}/{path.lstrip('/')}"
            await limiter.acquire()
            try:
                response = await client.get(url)
            except httpx.HTTPError:
                continue
            if response.status_code in _OWN_HIT_CODES:
                body, ctype = _readable(response)
                hits.append(
                    _Hit(
                        url=str(response.url),
                        status=response.status_code,
                        length=len(response.content),
                        tool="shaidra",
                        body=body,
                        ctype=ctype,
                    )
                )
    return hits


def _wordlist_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()


async def _enrich_bodies(ctx: ScanContext, bus: EventBus, hits: list[_Hit]) -> None:
    """Fetch bodies for hits reported by external tools (bounded, throttled).

    feroxbuster/ffuf report status and length only, so their hits arrive with
    no body. Fetch a bounded number of the reachable ones so the content scan
    still sees what the response actually contains. Hits from the built-in
    prober already carry their body and are skipped.
    """
    pending = [hit for hit in hits if not hit.body and hit.status == 200][:_BODY_FETCH_BUDGET]
    if not pending:
        return
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    async with make_http_client(ctx, follow_redirects=False, timeout=_OWN_TIMEOUT) as client:
        for hit in pending:
            await limiter.acquire()
            try:
                response = await client.get(hit.url)
            except httpx.HTTPError:
                continue
            if response.status_code == 200:
                hit.body, hit.ctype = _readable(response)


async def _catch_all_baseline(ctx: ScanContext, base: str) -> _Baseline | None:
    """Learn a server's catch-all response by requesting a random path.

    Many servers answer 200 with a generic page (SPA fallback, custom router)
    for every path. Without this baseline, a name-only classifier would report
    paths that do not really exist — and a browser clicking them lands on the
    app's 404. Returns None when even the probe fails.
    """
    probe = f"{base.rstrip('/')}/shaidra-{uuid.uuid4().hex}"
    async with make_http_client(ctx, follow_redirects=False, timeout=_OWN_TIMEOUT) as client:
        try:
            response = await client.get(probe)
        except httpx.HTTPError:
            return None
    body, ctype = _readable(response)
    return _Baseline(status=response.status_code, body=body, ctype=ctype)


async def _baselines(ctx: ScanContext, bases: Sequence[str]) -> dict[str, _Baseline]:
    """Learn a catch-all baseline per base host, keyed by URL netloc."""
    out: dict[str, _Baseline] = {}
    for base in bases:
        baseline = await _catch_all_baseline(ctx, base)
        if baseline is not None:
            out[_netloc(base)] = baseline
    return out


def _netloc(url: str) -> str:
    return urlsplit(url).netloc.lower()


def _readable(response: httpx.Response) -> tuple[str, str]:
    """Return a (bounded text body, content-type) pair for a response."""
    ctype = response.headers.get("content-type", "")
    if not _is_text(ctype):
        return "", ctype
    return response.text[:_BODY_CAP], ctype


def _is_text(content_type: str) -> bool:
    lowered = content_type.lower()
    return any(kind in lowered for kind in _TEXT_TYPES)


def _looks_like_catch_all(hit: _Hit, baseline: _Baseline) -> bool:
    """Return whether a hit is just the server's catch-all page, not real content.

    A hit matches the baseline when it has the same status and either an
    identical body or a near-identical one (same family, ~same size, same
    opening bytes) — the signature of a generic router/SPA fallback.
    """
    if baseline.status < 200 or baseline.status != hit.status:
        return False
    if not baseline.body or not hit.body:
        return False
    if _type_family(baseline.ctype) != _type_family(hit.ctype):
        return False
    left = _squash(hit.body)
    right = _squash(baseline.body)
    if left == right:
        return True
    if len(right) >= 200 and abs(len(left) - len(right)) <= max(32, int(0.02 * len(right))):
        return left[:128] == right[:128]
    return False


def _type_family(ctype: str) -> str:
    lowered = ctype.lower()
    for family in ("html", "json", "xml", "javascript"):
        if family in lowered:
            return family
    return "text"


def _squash(text: str) -> str:
    return " ".join(text.split())


async def _emit_findings(
    ctx: ScanContext, bus: EventBus, hits: list[_Hit], baselines: dict[str, _Baseline]
) -> int:
    emitted = 0
    secrets_seen: set[tuple[str, str]] = set()
    for index, hit in enumerate(hits, start=1):
        await bus.stage_progress(STAGE_NAME, index, len(hits))
        host = urlsplit(hit.url).hostname or ctx.target
        if not ctx.scope.in_scope(host):
            continue
        baseline = baselines.get(_netloc(hit.url))
        if baseline is not None and _looks_like_catch_all(hit, baseline):
            continue
        # Leaked credentials / PII inside the response body: the path name says
        # nothing about what a file contains, so this runs before the
        # name-based classification and independent of it.
        for match in scan_text(hit.body):
            key = (match.rule, match.redacted)
            if key in secrets_seen:
                continue
            secrets_seen.add(key)
            if emitted >= _MAX_FINDINGS:
                break
            emitted += 1
            await bus.finding(_secret_finding(host, hit, match))
        if emitted >= _MAX_FINDINGS:
            break
        path = urlsplit(hit.url).path or hit.url
        if is_known_exposure(path):
            continue
        severity = _sensitivity(path)
        if severity is None:
            continue
        severity = _clamp_by_status(severity, hit.status)
        emitted += 1
        await bus.finding(_path_finding(host, hit, path, severity))
    return emitted


def _path_finding(host: str, hit: _Hit, path: str, severity: Severity) -> Finding:
    return Finding(
        title=f"Sensitive path exposed: {path}",
        severity=severity,
        category=Category.CONTENT,
        host=host,
        tool=hit.tool,
        evidence=f"HTTP {hit.status}, {hit.length} bytes",
        url=hit.url,
        description=_describe(severity),
        raw={"status": hit.status, "content_length": hit.length},
    )


def _secret_finding(host: str, hit: _Hit, match: SecretMatch) -> Finding:
    return Finding(
        title=f"Exposed secret: {match.rule}",
        severity=match.severity,
        category=Category.SECRETS,
        host=host,
        tool=hit.tool,
        evidence=f"{match.rule} -> {match.redacted}",
        url=hit.url,
        description=f"{match.description} The value is redacted; treat it as live until proven otherwise.",
        reference=match.reference,
        raw={"rule": match.rule, "redacted": match.redacted},
    )


def _sensitivity(path: str) -> Severity | None:
    """Map a discovered path to a severity, or None when it is generic."""
    lowered = path.lower()
    for marker in _HIGH_MARKERS:
        if marker in lowered:
            return Severity.HIGH
    for marker in _MEDIUM_MARKERS:
        if marker in lowered:
            return Severity.MEDIUM
    for marker in _LOW_MARKERS:
        if marker in lowered:
            return Severity.LOW
    return None


def _clamp_by_status(severity: Severity, status: int) -> Severity:
    """Stop a redirect from masquerading as a high-value exposure.

    A 3xx response only shows the path exists — the body is usually a
    directory-slash redirect to an ordinary page, so it must never outrank
    the LOW "worth a look" tier the path name alone can justify.
    """
    if 300 <= status < 400 and severity in (Severity.HIGH, Severity.MEDIUM):
        return Severity.LOW
    return severity


def _describe(severity: Severity) -> str:
    match severity:
        case Severity.HIGH:
            return "A high-value sensitive file or directory is publicly reachable."
        case Severity.MEDIUM:
            return "An administrative or diagnostic endpoint is publicly reachable."
        case Severity.LOW:
            return "A potentially sensitive path is reachable and worth manual review."
        case _:
            return "Sensitive content is reachable on the target."


def _wordlist_entries(path: Path) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    return sum(1 for line in text.splitlines() if line.strip() and not line.startswith("#"))


def _ferox_line(line: str) -> _Hit | None:
    try:
        payload: JsonValue = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return _hit_from(payload, "feroxbuster")


def _ffuf_stdout(stdout: str) -> list[_Hit]:
    try:
        payload: JsonValue = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, dict):
        return []
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    hits: list[_Hit] = []
    for entry in results:
        if not isinstance(entry, dict):
            continue
        hit = _hit_from(entry, "ffuf")
        if hit is not None:
            hits.append(hit)
    return hits[:_MAX_HITS]


def _hit_from(entry: Mapping[str, JsonValue], tool: str) -> _Hit | None:
    url = entry.get("url")
    if not isinstance(url, str) or not url:
        return None
    status = _as_int(entry.get("status"))
    if status is None:
        return None
    length = _as_int(entry.get("content_length"))
    if length is None:
        length = _as_int(entry.get("length"))
    return _Hit(url=url, status=status, length=length or 0, tool=tool)


def _as_int(value: JsonValue | None) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.lstrip("-").isdigit():
        return int(value)
    return None
