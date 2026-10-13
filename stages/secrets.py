"""Secret scanning: look for leaked credentials in the bodies Shaidra fetches.

The stage walks the URLs discovered by the crawl (falling back to the target
root) and runs the regex rule engine in :mod:`shaidra.utils.secrets` over each
text response. Because secrets most often sit in JavaScript bundles, every HTML
page it fetches is also mined for same-origin script/JSON/XML assets, which are
fetched and scanned in turn.

Detection is passive: bodies are only fetched, never mutated. Every match is
reported redacted, and duplicates (same rule and same redacted value) are
collapsed across the whole run so one leaked key on many pages is one finding.
"""

from __future__ import annotations

import re
from typing import Final
from urllib.parse import urljoin, urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, ScanContext
from shaidra.utils.rate_limiter import RateLimiter
from shaidra.utils.secrets import SecretMatch, scan_text

STAGE_NAME: Final[str] = "Secret scan"
TOOL: Final[str] = "shaidra"
_MAX_URLS: Final[int] = 200
_MAX_FINDINGS: Final[int] = 60
_BODY_CAP: Final[int] = 512 * 1024
_TIMEOUT: Final[float] = 12.0
_TEXT_TYPES: Final[tuple[str, ...]] = (
    "text/", "application/json", "application/javascript", "application/xml",
    "application/x-javascript", "+json", "+xml", "application/ld+json",
)
_ASSET_RE: Final[re.Pattern[str]] = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_ASSET_EXT: Final[tuple[str, ...]] = (".js", ".mjs", ".json", ".xml", ".map", ".txt")


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Scan crawled response bodies for exposed secrets."""
    await bus.stage_start(STAGE_NAME)
    if not ctx.web_reachable:
        await bus.stage_skip(STAGE_NAME, "target not reachable")
        return
    queue = _scan_targets(ctx)
    if not queue:
        await bus.stage_skip(STAGE_NAME, "no in-scope URLs to scan")
        return
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    seen_secrets: set[tuple[str, str]] = set()
    seen_urls: set[str] = set(queue)
    found = 0
    scanned = 0
    async with httpx.AsyncClient(follow_redirects=False, timeout=_TIMEOUT) as client:
        while queue and found < _MAX_FINDINGS and scanned < _MAX_URLS:
            url = queue.pop(0)
            scanned += 1
            await bus.stage_progress(STAGE_NAME, scanned, min(_MAX_URLS, scanned + len(queue)))
            page = await _fetch(client, limiter, url)
            if page is None:
                continue
            body, is_html = page
            for match in scan_text(body):
                key = (match.rule, match.redacted)
                if key in seen_secrets:
                    continue
                seen_secrets.add(key)
                found += 1
                await bus.finding(_build_finding(ctx, url, match))
                if found >= _MAX_FINDINGS:
                    break
            if is_html:
                for asset in _extract_assets(url, body, ctx, seen_urls):
                    queue.append(asset)
    await bus.stage_done(STAGE_NAME, f"{found} secret(s) in {scanned} URL(s)")


def _scan_targets(ctx: ScanContext) -> list[str]:
    """Return in-scope seed URLs to scan: target first, then crawled, capped and unique."""
    urls: list[str] = []
    seen: set[str] = set()

    def add(raw: str) -> None:
        url = raw.split("#", 1)[0]
        if not url or url in seen:
            return
        host = urlsplit(url).hostname
        if host is None or not ctx.scope.in_scope(host):
            return
        seen.add(url)
        urls.append(url)

    add(ctx.target_url)
    for url in ctx.crawled_urls:
        if len(urls) >= _MAX_URLS:
            break
        add(url)
    return urls


def _extract_assets(
    page_url: str, body: str, ctx: ScanContext, seen_urls: set[str]
) -> list[str]:
    """Return same-origin script/data assets referenced by an HTML page."""
    assets: list[str] = []
    for reference in _ASSET_RE.findall(body):
        ref = reference.strip()
        if not ref or ref.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        absolute = urljoin(page_url, ref.split("#", 1)[0])
        if absolute in seen_urls:
            continue
        if not absolute.lower().split("?", 1)[0].endswith(_ASSET_EXT):
            continue
        host = urlsplit(absolute).hostname
        if host is None or not ctx.scope.in_scope(host):
            continue
        if len(seen_urls) >= _MAX_URLS:
            break
        seen_urls.add(absolute)
        assets.append(absolute)
    return assets


async def _fetch(
    client: httpx.AsyncClient, limiter: RateLimiter, url: str
) -> tuple[str, bool] | None:
    """Fetch a URL and return its body plus an is-HTML flag, or None."""
    await limiter.acquire()
    try:
        async with client.stream("GET", url) as response:
            content_type = response.headers.get("content-type", "")
            if response.status_code != 200 or not _is_text(content_type):
                return None
            buffer = bytearray()
            async for chunk in response.aiter_bytes():
                buffer.extend(chunk)
                if len(buffer) >= _BODY_CAP:
                    break
    except httpx.HTTPError:
        return None
    return buffer.decode("utf-8", "replace"), "html" in content_type.lower()


def _is_text(content_type: str) -> bool:
    """Report whether a content type is worth scanning (defaults to yes when absent)."""
    if not content_type:
        return True
    lowered = content_type.lower()
    return any(marker in lowered for marker in _TEXT_TYPES)


def _build_finding(ctx: ScanContext, url: str, match: SecretMatch) -> Finding:
    """Assemble a redacted finding for one secret occurrence."""
    host = urlsplit(url).hostname or ctx.target
    return Finding(
        title=f"Exposed secret: {match.rule}",
        severity=match.severity,
        category=Category.SECRETS,
        host=host,
        tool=TOOL,
        evidence=f"{match.rule} -> {match.redacted}",
        url=url,
        description=f"{match.description} The value is shown redacted.",
        reference=match.reference,
        raw={"rule": match.rule, "redacted": match.redacted},
    )
