"""Fingerprinting stage: detect CMS and server technology on live hosts.

For every host confirmed live by recon, this stage fetches the page with the
python httpx library, fingerprints CMS products from body markers and headers
(WordPress, Joomla, Drupal, Magento, Shopify), records server/X-Powered-By
tech, and optionally merges WhatWeb output when that tool is installed.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Iterable
from typing import Final

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Host, LogLevel, ScanContext
from shaidra.utils.process import RunOptions, run_tool
from shaidra.utils.rate_limiter import RateLimiter

STAGE: Final[str] = "fingerprint"
FETCH_TIMEOUT: Final[float] = 10.0
FETCH_CONCURRENCY: Final[int] = 10
BODY_SCAN_CAP: Final[int] = 200_000
_WORDPRESS_TOKEN: Final[str] = "wordpress"
_GENERATOR_RE: Final[re.Pattern[str]] = re.compile(
    r"""name=['"]generator['"]\s+content=['"]([^'"]+)""", re.IGNORECASE
)
_CMS_NAMES: Final[tuple[str, ...]] = ("wordpress", "joomla", "drupal")
_BODY_MARKERS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("wordpress", ("wp-content", "wp-includes", "wp-login.php")),
    ("joomla", ("/media/system/js/", "com_content")),
    ("drupal", ("drupal.settings", "drupal-settings-json", "sites/default/files")),
    ("magento", ("mage/", "/static/version", "magento")),
    ("shopify", ("cdn.shopify.com", "shopify.theme")),
)


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Enrich every live host with detected CMS and server technology."""
    await bus.stage_start(STAGE)
    hosts = ctx.live_hosts()
    if not hosts:
        await bus.log("No live hosts to fingerprint.", LogLevel.INFO)
        await bus.stage_done(STAGE, "no live hosts")
        return
    limiter = RateLimiter(float(ctx.rate_limit))
    sem = asyncio.Semaphore(FETCH_CONCURRENCY)
    done = 0

    async with httpx.AsyncClient(follow_redirects=True, timeout=FETCH_TIMEOUT, verify=False) as client:

        async def process(host: Host) -> None:
            nonlocal done
            await limiter.acquire()
            url = host.url or f"{host.scheme or 'https'}://{host.host}"
            async with sem:
                tokens = await _detect_tech(client, url)
            done += 1
            await bus.stage_progress(STAGE, done, len(hosts))
            if tokens is None:
                await bus.log(f"Fingerprint {host.host}: unreachable.", LogLevel.WARN)
                return
            _merge_tech(host, tokens)
            _merge_tech(host, await _whatweb_tokens(ctx, url))
            _ensure_wordpress(host)
            summary = ", ".join(host.tech) if host.tech else "no technologies detected"
            await bus.log(f"Fingerprint {host.host}: {summary}.")
            await bus.host(host)

        await asyncio.gather(*(process(h) for h in hosts), return_exceptions=True)
    await bus.stage_done(STAGE, f"processed {len(hosts)} live host(s)")


async def _detect_tech(client: httpx.AsyncClient, url: str) -> list[str] | None:
    """Fetch url and return tech tokens; None when the host is unreachable."""
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return None
    body = resp.text[:BODY_SCAN_CAP]
    lowered = body.lower()
    tokens: list[str] = []
    for token, markers in _BODY_MARKERS:
        if any(marker in lowered for marker in markers):
            tokens.append(token)
    generator = _find_generator(body)
    if generator is not None:
        for name in _CMS_NAMES:
            if name in generator and name not in tokens:
                tokens.append(name)
    for header in ("server", "x-powered-by", "x-generator"):
        value = resp.headers.get(header)
        if value:
            tokens.append(value)
            if header == "x-generator":
                lowered_gen = value.lower()
                for name in _CMS_NAMES:
                    if name in lowered_gen and name not in tokens:
                        tokens.append(name)
    return tokens


def _find_generator(body: str) -> str | None:
    match = _GENERATOR_RE.search(body)
    return match.group(1).lower() if match is not None else None


async def _whatweb_tokens(ctx: ScanContext, url: str) -> list[str]:
    """Return WhatWeb plugin names, or [] when the tool is missing or fails."""
    if not ctx.has_tool("whatweb"):
        return []
    result = await run_tool(
        ["whatweb", "-q", "--log-json=-", url],
        RunOptions(timeout=float(ctx.config.timeout_for("whatweb", 300))),
    )
    if not result.ok:
        return []
    try:
        raw: object = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    if not isinstance(raw, list):
        return []
    tokens: list[str] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        plugins = entry.get("plugins")
        if isinstance(plugins, dict):
            tokens.extend(name for name in plugins if isinstance(name, str))
    return tokens


def _merge_tech(host: Host, tokens: Iterable[str]) -> None:
    """Append tokens to host.tech, deduplicating case-insensitively."""
    seen = {t.casefold() for t in host.tech}
    for token in tokens:
        cleaned = token.strip()
        if not cleaned:
            continue
        key = cleaned.casefold()
        if key not in seen:
            host.tech.append(cleaned)
            seen.add(key)


def _ensure_wordpress(host: Host) -> None:
    """Guarantee the literal lowercase token `wordpress` when WordPress is present."""
    if _WORDPRESS_TOKEN in host.tech:
        return
    if any(t.casefold() == _WORDPRESS_TOKEN for t in host.tech):
        host.tech.append(_WORDPRESS_TOKEN)
