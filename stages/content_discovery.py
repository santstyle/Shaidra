"""Content discovery: find sensitive paths exposed by the target web server.

Prefers feroxbuster, falls back to ffuf, and skips cleanly when neither tool
or a usable wordlist is available. Only paths classified as sensitive produce
findings; generic 200 responses are counted but never reported.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, JsonValue, LogLevel, ScanContext, Severity
from shaidra.utils.process import RunOptions, run_tool, stream_lines
from shaidra.utils.rate_limiter import RateLimiter

STAGE_NAME: Final[str] = "Content discovery"
_STATUS_CODES: Final[str] = "200,204,301,302,307,401,403"
_MAX_HITS: Final[int] = 500
_MAX_FINDINGS: Final[int] = 40
_PROGRESS_EVERY: Final[int] = 25
_OWN_BUDGET: Final[int] = 400
_OWN_TIMEOUT: Final[float] = 10.0
_OWN_HIT_CODES: Final[frozenset[int]] = frozenset({200, 204, 301, 302, 307, 401, 403})

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


@dataclass(frozen=True, slots=True)
class _Hit:
    url: str
    status: int
    length: int
    tool: str


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Enumerate sensitive content paths on the target base URL."""
    await bus.stage_start(STAGE_NAME)
    if not ctx.scope.in_scope(ctx.target_url):
        await bus.stage_skip(STAGE_NAME, "target out of scope")
        return
    wordlist = _resolve_wordlist(ctx.config.wordlist_content)
    if wordlist is None:
        await bus.stage_skip(STAGE_NAME, f"content wordlist not found: {ctx.config.wordlist_content}")
        return
    hits: list[_Hit]
    if ctx.has_tool("feroxbuster"):
        hits = await _feroxbuster_hits(ctx, wordlist, bus)
    elif ctx.has_tool("ffuf"):
        hits = await _ffuf_hits(ctx, wordlist)
    elif ctx.web_reachable:
        await bus.log("feroxbuster and ffuf not installed; using built-in wordlist probing", LogLevel.WARN)
        hits = await _own_hits(ctx, wordlist, bus)
    else:
        await bus.stage_skip(STAGE_NAME, "feroxbuster and ffuf not installed and target not reachable")
        return
    emitted = await _emit_findings(ctx, bus, hits)
    await bus.stage_done(STAGE_NAME, f"{emitted} sensitive paths from {len(hits)} responses")


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


async def _feroxbuster_hits(ctx: ScanContext, wordlist: Path, bus: EventBus) -> list[_Hit]:
    argv = [
        "feroxbuster", "-u", ctx.target_url, "--json", "-w", str(wordlist),
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


async def _ffuf_hits(ctx: ScanContext, wordlist: Path) -> list[_Hit]:
    argv = [
        "ffuf", "-u", f"{ctx.target_url.rstrip('/')}/FUZZ", "-w", str(wordlist),
        "-mc", _STATUS_CODES, "-of", "json", "-o", "-", "-s",
    ]
    options = RunOptions(timeout=ctx.config.timeout_for("ffuf"))
    result = await run_tool(argv, options)
    return _ffuf_stdout(result.stdout)


async def _own_hits(ctx: ScanContext, wordlist: Path, bus: EventBus) -> list[_Hit]:
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
    base = ctx.target_url.rstrip("/")
    async with httpx.AsyncClient(follow_redirects=False, timeout=_OWN_TIMEOUT) as client:
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
                hits.append(
                    _Hit(
                        url=str(response.url),
                        status=response.status_code,
                        length=len(response.content),
                        tool="shaidra",
                    )
                )
    return hits


def _wordlist_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()


async def _emit_findings(ctx: ScanContext, bus: EventBus, hits: list[_Hit]) -> int:
    emitted = 0
    for index, hit in enumerate(hits, start=1):
        await bus.stage_progress(STAGE_NAME, index, len(hits))
        path = urlsplit(hit.url).path or hit.url
        severity = _sensitivity(path)
        if severity is None:
            continue
        if emitted >= _MAX_FINDINGS:
            break
        host = urlsplit(hit.url).hostname or ctx.target
        if not ctx.scope.in_scope(host):
            continue
        emitted += 1
        await bus.finding(
            Finding(
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
        )
    return emitted


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
