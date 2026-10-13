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
from shaidra.utils.http import make_http_client
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
# SPA/API targets expose most of their real routes in robots.txt, sitemap.xml
# and JS bundles rather than in <a href>/<form>, so the built-in spider mines
# those too — otherwise the web-vuln and redirect stages get nothing to probe.
_ROBOTS_RULE_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:allow|disallow)\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE
)
_ROBOTS_SITEMAP_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*sitemap\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE
)
_SITEMAP_LOC_RE: Final[re.Pattern[str]] = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_SCRIPT_SRC_RE: Final[re.Pattern[str]] = re.compile(
    r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.IGNORECASE
)
_SCRIPT_BODY_RE: Final[re.Pattern[str]] = re.compile(r"<script\b[^>]*>([\s\S]*?)</script>", re.IGNORECASE)
_JS_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"""["'`]((?:https?://|/)[A-Za-z0-9_\-./?=&%:~+#]{1,300})["'`]"""
)
_MAX_META_URLS: Final[int] = 150
_MAX_JS_FILES: Final[int] = 12

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
    action targets, plus endpoints mined from robots.txt, sitemap.xml and
    JavaScript (inline and linked bundles). This surfaces real application
    routes and hidden parameters — not just the bare base URL — so the web-vuln
    and redirect stages have something to test. Every request is throttled
    through RateLimiter and nothing is written to the target.
    """
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    discovered: dict[str, None] = {}
    frontier: list[tuple[str, int]] = [(seed, 0) for seed in seeds]
    seen_forms: set[tuple[str, str, tuple[str, ...]]] = set()
    fetched = 0
    js_fetched = 0
    async with make_http_client(ctx, follow_redirects=True, timeout=SPIDER_TIMEOUT, verify=False) as client:
        for meta_url in await _meta_urls(ctx, client, limiter, seeds):
            if meta_url not in discovered:
                frontier.append((meta_url, 1))
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
            for reference in [*_extract_refs(body), *_inline_js_refs(body)]:
                absolute = urljoin(url, reference)
                if not _keep_url(absolute):
                    continue
                if not ctx.scope.in_scope(absolute):
                    continue
                if absolute not in discovered:
                    frontier.append((absolute, depth + 1))
            if js_fetched < _MAX_JS_FILES:
                for reference in _script_srcs(body):
                    if js_fetched >= _MAX_JS_FILES:
                        break
                    absolute = urljoin(url, reference)
                    if not _kept_script(absolute) or not ctx.scope.in_scope(absolute):
                        continue
                    js_fetched += 1
                    script = await _fetch_text(client, limiter, absolute)
                    for mined in _js_refs(script):
                        candidate = urljoin(absolute, mined)
                        if _keep_url(candidate) and ctx.scope.in_scope(candidate) and candidate not in discovered:
                            frontier.append((candidate, depth + 1))
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


async def _meta_urls(
    ctx: ScanContext, client: httpx.AsyncClient, limiter: RateLimiter, seeds: Sequence[str]
) -> list[str]:
    """Collect candidate URLs from robots.txt and sitemap.xml for each seed.

    robots.txt frequently lists disallowed (yet reachable) admin/API paths, and
    sitemap.xml enumerates real pages — routes the HTML itself rarely links to.
    Anything out of scope is dropped before it reaches the crawl frontier.
    """
    found: dict[str, None] = {}
    for base in seeds:
        root = base.rstrip("/") + "/"
        robots = await _fetch_text(client, limiter, urljoin(root, "robots.txt"))
        sitemaps = [urljoin(root, "sitemap.xml")]
        if robots:
            for match in _ROBOTS_RULE_RE.finditer(robots):
                path = match.group(1).strip()
                if not path or path == "*":
                    continue
                if path.startswith(("http://", "https://")):
                    found[path] = None
                elif path != "/":
                    found[urljoin(root, path.lstrip("/"))] = None
            sitemaps.extend(match.group(1).strip() for match in _ROBOTS_SITEMAP_RE.finditer(robots))
        for sitemap in sitemaps:
            for url in await _sitemap_urls(client, limiter, sitemap):
                found[url] = None
        if len(found) >= _MAX_META_URLS:
            break
    return [url for url in found if ctx.scope.in_scope(url)][:_MAX_META_URLS]


async def _sitemap_urls(client: httpx.AsyncClient, limiter: RateLimiter, url: str) -> list[str]:
    """Return the ``<loc>`` targets of a sitemap, or nothing if it is not one."""
    body = await _fetch_text(client, limiter, url)
    if not body or "<loc" not in body.lower():
        return []
    return [match.group(1).strip() for match in _SITEMAP_LOC_RE.finditer(body)]


async def _fetch_text(client: httpx.AsyncClient, limiter: RateLimiter, url: str) -> str:
    """Fetch a text asset (robots.txt, sitemap.xml, JS) under the body cap."""
    await limiter.acquire()
    try:
        response = await client.get(url)
    except httpx.HTTPError:
        return ""
    if response.status_code != 200 or len(response.content) > _SPIDER_BODY_CAP:
        return ""
    return response.text


def _script_srcs(body: str) -> list[str]:
    """Return the ``src`` targets of a page's ``<script>`` tags."""
    return _SCRIPT_SRC_RE.findall(body)


def _inline_js_refs(body: str) -> list[str]:
    """Return endpoint-looking string literals from a page's inline scripts."""
    refs: list[str] = []
    for script in _SCRIPT_BODY_RE.findall(body):
        refs.extend(_js_refs(script))
    return refs


def _js_refs(js_text: str) -> list[str]:
    """Return quoted path/URL literals found in JavaScript source."""
    if not js_text:
        return []
    refs: list[str] = []
    for value in _JS_PATH_RE.findall(js_text):
        target = value.strip()
        if target in ("/", "//") or target.startswith("//"):
            continue
        refs.append(target)
    return refs


def _kept_script(url: str) -> bool:
    """Keep same-origin JavaScript bundle URLs that :func:`_keep_url` drops."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    return parts.path.lower().endswith((".js", ".mjs"))


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
