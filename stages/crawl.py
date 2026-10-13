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
from collections.abc import Sequence
from typing import Final, Literal

from shaidra.core.events import EventBus
from shaidra.core.models import JsonValue, LogLevel, ScanContext
from shaidra.utils.process import RunOptions, stream_lines

STAGE_NAME: Final[str] = "Crawl"
MAX_URLS: Final[int] = 2000
MAX_BASES: Final[int] = 3
_MAX_RAW: Final[int] = 4000
_SCHEMES: Final[tuple[str, ...]] = ("http://", "https://")

Crawler = Literal["katana", "gau", "waybackurls"]


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Discover in-scope URLs and publish them on ``ctx.crawled_urls``."""
    await bus.stage_start(STAGE_NAME)
    seeds = _base_urls(ctx)
    tools = _select_tools(ctx)
    raw = list(seeds)
    if not tools:
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
