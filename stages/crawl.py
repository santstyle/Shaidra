"""URL discovery that feeds the webvuln and open-redirect stages (Category.WEBVULN).

Fills ``ctx.crawled_urls`` with in-scope URLs — parameterized ones in
particular — so this stage must run before webvuln and open_redirect.
Discovery is passive and read-only: katana crawls without a proxy, gau and
waybackurls replay URL archives. No findings are produced here. When no
crawler is installed the stage still seeds the live base URLs, because
downstream stages depend on this stage producing input.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Final, Literal
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import FormTarget, JsonValue, LogLevel, ScanContext
from shaidra.utils.process import RunOptions, stream_lines
from shaidra.utils.rate_limiter import RateLimiter

STAGE_NAME: Final[str] = "Crawl"
MAX_URLS: Final[int] = 2000
MAX_BASES: Final[int] = 3
_MAX_RAW: Final[int] = 4000
_SCHEMES: Final[tuple[str, ...]] = ("http://", "https://")
SPIDER_MAX_PAGES: Final[int] = 80
_MAX_FORM_FIELDS: Final[int] = 24
_MAX_FORMS: Final[int] = 300
SPIDER_DEPTH: Final[int] = 3
SPIDER_TIMEOUT: Final[float] = 10.0
_SPIDER_BODY_CAP: Final[int] = 250_000
_SPIDER_ATTR_RE: Final[re.Pattern[str]] = re.compile(
    r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_SPIDER_FORM_RE: Final[re.Pattern[str]] = re.compile(r"<form[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_SPIDER_METHOD_RE: Final[re.Pattern[str]] = re.compile(r"""method\s*=\s*["']post["']""", re.IGNORECASE)
_SPIDER_ACTION_RE: Final[re.Pattern[str]] = re.compile(r"""action\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_SPIDER_INPUT_NAME_RE: Final[re.Pattern[str]] = re.compile(r"""<input[^>]*name=["']([^"']+)["'][^>]*>""", re.IGNORECASE)
_SPIDER_INPUT_TAG_RE: Final[re.Pattern[str]] = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_SPIDER_TEXTAREA_TAG_RE: Final[re.Pattern[str]] = re.compile(r"<textarea\b[^>]*>", re.IGNORECASE)
_SPIDER_SELECT_TAG_RE: Final[re.Pattern[str]] = re.compile(r"<select\b[^>]*>", re.IGNORECASE)
_SPIDER_TAG_NAME_RE: Final[re.Pattern[str]] = re.compile(r"""\bname\s*=\s*["']?([^"'\s>/]+)""", re.IGNORECASE)
_SPIDER_TAG_VALUE_RE: Final[re.Pattern[str]] = re.compile(r"""\bvalue\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_SPIDER_TAG_TYPE_RE: Final[re.Pattern[str]] = re.compile(r"""\btype\s*=\s*["']?([^"'\s>/]+)""", re.IGNORECASE)
_SPIDER_CSRF_RE: Final[re.Pattern[str]] = re.compile(r"(csrf|xsrf|authenticity|nonce|_token|token)", re.IGNORECASE)
_SPIDER_SKIP_INPUT_RE: Final[frozenset[str]] = frozenset({"submit", "button", "image", "reset", "file"})
_SPIDER_SKIP_EXT: Final[frozenset[str]] = frozenset({
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".pdf",
})

Crawler = Literal["katana", "gau", "waybackurls"]


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Discover in-scope URLs and publish them on ``ctx.crawled_urls``."""
    await bus.stage_start(STAGE_NAME)
    seeds = _base_urls(ctx)
    tools = _select_tools(ctx)
    raw = list(seeds)
    if not tools:
        if ctx.web_reachable:
            await bus.log(
                "No crawler installed (katana, gau, waybackurls); using built-in spider",
                LogLevel.WARN,
            )
            raw = list(await _spider(ctx, bus, seeds))
        else:
            await bus.log("No crawler installed (katana, gau, waybackurls); base URLs only", LogLevel.WARN)
    for index, tool in enumerate(tools, start=1):
        raw.extend(await _collect(ctx, tool))
        await bus.stage_progress(STAGE_NAME, index, len(tools))
    urls = _finalize(ctx, raw, seeds)
    ctx.crawled_urls = urls
    sources = ", ".join(tools) if tools else "base seeds"
    await bus.log(f"Crawl finished: {len(urls)} in-scope URLs from {sources}")
    detail = f"{len(urls)} URLs" if tools else f"{len(urls)} base URLs (no crawler installed)"
    await bus.stage_done(STAGE_NAME, detail)


def _select_tools(ctx: ScanContext) -> list[Crawler]:
    """Pick katana plus the preferred archive source (gau, else waybackurls)."""
    tools: list[Crawler] = []
    if ctx.has_tool("katana"):
        tools.append("katana")
    if ctx.has_tool("gau"):
        tools.append("gau")
    elif ctx.has_tool("waybackurls"):
        tools.append("waybackurls")
    return tools


async def _spider(ctx: ScanContext, bus: EventBus, seeds: Sequence[str]) -> list[str]:
    """Depth-limited same-origin crawler used when no external crawler exists.

    Fetches each seed and the in-scope HTML it links to, extracting href/src/
    action targets so downstream stages see real application routes (login
    pages, API docs, forms) instead of only the bare base URL. Every request
    is throttled through RateLimiter and nothing is written to the target.
    """
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    discovered: dict[str, None] = {}
    frontier: list[tuple[str, int]] = [(seed, 0) for seed in seeds]
    seen_forms: set[tuple[str, str, tuple[str, ...]]] = set()
    fetched = 0
    async with httpx.AsyncClient(follow_redirects=True, timeout=SPIDER_TIMEOUT, verify=False) as client:
        while frontier and len(discovered) < MAX_URLS:
            url, depth = frontier.pop(0)
            if url in discovered:
                continue
            discovered[url] = None
            if depth >= SPIDER_DEPTH or fetched >= SPIDER_MAX_PAGES:
                continue
            await limiter.acquire()
            fetched += 1
            await bus.stage_progress(STAGE_NAME, fetched, 0)
            body = ""
            try:
                response = await client.get(url)
                content_type = response.headers.get("content-type", "")
                if response.status_code == 200 and "html" in content_type.lower():
                    body = response.text[:_SPIDER_BODY_CAP]
            except httpx.HTTPError:
                continue
            for reference in _extract_refs(body):
                absolute = urljoin(url, reference)
                if not _keep_url(absolute):
                    continue
                if not ctx.scope.in_scope(absolute):
                    continue
                if absolute not in discovered:
                    frontier.append((absolute, depth + 1))
            for query_url in _form_query_urls(url, body):
                if not ctx.scope.in_scope(query_url):
                    continue
                discovered[query_url] = None
            for target in _form_targets(url, body):
                if not ctx.scope.in_scope(target.action_url):
                    continue
                key = (target.action_url, target.method, tuple(sorted(target.fields)))
                if key in seen_forms:
                    continue
                seen_forms.add(key)
                ctx.form_targets.append(target)
                if len(ctx.form_targets) >= _MAX_FORMS:
                    break
    return list(discovered)[:MAX_URLS]


def _form_query_urls(page_url: str, body: str) -> list[str]:
    """Build candidate URLs from GET forms so their fields get tested.

    A GET form (the default method) submits through the query string, so
    discovering only the action URL hides the very parameters that later
    stages probe. Each form yields one URL per input name with a blank value,
    e.g. ``/search.jsp?query=``.
    """
    urls: list[str] = []
    for form in _SPIDER_FORM_RE.findall(body):
        if _SPIDER_METHOD_RE.search(form):
            continue
        action = _SPIDER_ACTION_RE.search(form)
        raw_action = (action.group(1) if action else "").strip()
        target = page_url if raw_action in ("", "#") else urljoin(page_url, raw_action)
        names = _SPIDER_INPUT_NAME_RE.findall(form)
        if not names:
            continue
        if not _keep_url(target):
            continue
        parts = urlsplit(target)
        # Drop any fragment: a query placed after "#" is never sent to the
        # server, which silently hides the parameter from later probes.
        base = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
        separator = "&" if parts.query else "?"
        for name in dict.fromkeys(names):
            urls.append(f"{base}{separator}{name}=")
            if len(urls) >= _MAX_FORM_FIELDS:
                return urls
    return urls


def _form_targets(page_url: str, body: str) -> list[FormTarget]:
    """Parse server-rendered forms into probeable :class:`FormTarget` records.

    Only the built-in spider builds these. They let the web-vuln stage submit
    POST bodies and named GET fields that query-string discovery alone misses.
    """
    targets: list[FormTarget] = []
    for form in _SPIDER_FORM_RE.findall(body):
        action = _SPIDER_ACTION_RE.search(form)
        raw_action = (action.group(1) if action else "").strip()
        target_url = page_url if raw_action in ("", "#") else urljoin(page_url, raw_action)
        if not _keep_url(target_url):
            continue
        fields = _form_fields(form)
        if not fields:
            continue
        method = "POST" if _SPIDER_METHOD_RE.search(form) else "GET"
        has_token = any(_SPIDER_CSRF_RE.search(name) for name in fields)
        targets.append(
            FormTarget(
                page_url=page_url,
                action_url=target_url,
                method=method,
                fields=fields,
                has_csrf_token=has_token,
            )
        )
    return targets


def _form_fields(form: str) -> dict[str, str]:
    """Collect name/value pairs from a form's input, textarea, and select tags."""
    tags = (
        *_SPIDER_INPUT_TAG_RE.findall(form),
        *_SPIDER_TEXTAREA_TAG_RE.findall(form),
        *_SPIDER_SELECT_TAG_RE.findall(form),
    )
    fields: dict[str, str] = {}
    for tag in tags:
        type_match = _SPIDER_TAG_TYPE_RE.search(tag)
        if type_match and type_match.group(1).lower() in _SPIDER_SKIP_INPUT_RE:
            continue
        name_match = _SPIDER_TAG_NAME_RE.search(tag)
        if name_match is None:
            continue
        value_match = _SPIDER_TAG_VALUE_RE.search(tag)
        fields.setdefault(name_match.group(1), value_match.group(1) if value_match else "")
        if len(fields) >= _MAX_FORM_FIELDS:
            break
    return fields


def _extract_refs(body: str) -> list[str]:
    """Return the href/src/action targets referenced by an HTML page."""
    refs: list[str] = []
    for value in _SPIDER_ATTR_RE.findall(body):
        target = value.strip()
        if not target or target.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        refs.append(target)
    return refs


def _keep_url(url: str) -> bool:
    """Keep http(s) URLs that are not static-asset downloads."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    path = parts.path.lower()
    return not path.endswith(tuple(_SPIDER_SKIP_EXT))


async def _collect(ctx: ScanContext, tool: Crawler) -> list[str]:
    match tool:
        case "katana":
            return await _katana_urls(ctx)
        case "gau":
            return await _archive_urls(ctx, ("gau", "--threads", "5"))
        case "waybackurls":
            return await _archive_urls(ctx, ("waybackurls",))
        case _:
            return []


async def _katana_urls(ctx: ScanContext) -> list[str]:
    options = RunOptions(timeout=float(ctx.config.timeout_for("katana")))
    depth = str(ctx.config.katana_depth)
    rate = str(ctx.config.lowered_rate() if ctx.waf else ctx.rate_limit)
    urls: list[str] = []
    for base in _base_urls(ctx):
        argv = ["katana", "-u", base, "-silent", "-jsonl", "-d", depth, "-jc", "-kf", "all", "-rl", rate]
        async for line in stream_lines(argv, options):
            url = _katana_url(line)
            if url:
                urls.append(url)
            if len(urls) >= _MAX_RAW:
                return urls
    return urls


async def _archive_urls(ctx: ScanContext, prefix: Sequence[str]) -> list[str]:
    options = RunOptions(timeout=float(ctx.config.timeout_for(prefix[0])))
    urls: list[str] = []
    for host in _crawl_hosts(ctx):
        urls.extend(await _stream_urls([*prefix, host], options))
    return urls


async def _stream_urls(argv: Sequence[str], options: RunOptions) -> list[str]:
    urls: list[str] = []
    async for line in stream_lines(argv, options):
        urls.append(line)
        if len(urls) >= _MAX_RAW:
            break
    return urls


def _katana_url(line: str) -> str:
    payload = _load_object(line)
    if payload is None:
        return ""
    request = payload.get("request")
    if isinstance(request, dict):
        for key in ("endpoint", "url"):
            value = request.get(key)
            if isinstance(value, str) and value:
                return value
    url = payload.get("url")
    return url if isinstance(url, str) else ""


def _load_object(line: str) -> dict[str, JsonValue] | None:
    try:
        payload: JsonValue = json.loads(line)
    except json.JSONDecodeError:
        return None
    if isinstance(payload, dict):
        return payload
    return None


def _base_urls(ctx: ScanContext) -> list[str]:
    candidates = [ctx.target_url, *(host.url for host in ctx.live_hosts() if host.url)]
    bases: dict[str, None] = {}
    for candidate in candidates:
        clean = candidate.strip().rstrip("/")
        if clean.startswith(_SCHEMES) and ctx.scope.in_scope(clean):
            bases[clean] = None
        if len(bases) >= MAX_BASES:
            break
    return list(bases)


def _crawl_hosts(ctx: ScanContext) -> list[str]:
    hosts: dict[str, None] = {ctx.target: None}
    for host in ctx.live_hosts():
        if ctx.scope.in_scope(host.host):
            hosts[host.host] = None
        if len(hosts) >= MAX_BASES:
            break
    return list(hosts)


def _finalize(ctx: ScanContext, raw: list[str], seeds: list[str]) -> list[str]:
    urls: dict[str, None] = {}
    for candidate in raw:
        clean = candidate.strip()
        if not clean.startswith(_SCHEMES):
            continue
        if not ctx.scope.in_scope(clean):
            continue
        urls[clean] = None
        if len(urls) >= MAX_URLS:
            break
    if urls:
        return list(urls)
    return seeds or [ctx.target_url]
