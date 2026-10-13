"""Scan orchestration: wires the pipeline stages together over the event bus.

The run is split into three phases:

* Stage 0 - preflight: discover external tools, run WAF detection, and lower the
  rate limit if a WAF is present.
* Stage 1 - recon: enumerate subdomains, probe for live hosts, and fingerprint
  the tech stack. Every later stage operates on the hosts this phase confirms.
* Stage 2 - scanning: run the vulnerability stages in parallel. Crawl is a
  prerequisite for the stages that consume discovered URLs, so those run in a
  second wave while the independent stages run in the first.

A stage never raises by contract; the guarded runner here is a supervisor
backstop so a single unexpected failure cannot abort the whole scan.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Final

from shaidra.core.events import EventBus
from shaidra.core.models import Category, LogLevel, ScanContext
from shaidra.core.waf_detect import detect_waf
from shaidra.output.visual import capture_screenshots
from shaidra.stages import (
    api_scan,
    cms_scan,
    content_discovery,
    cors,
    crawl,
    cve_match,
    fingerprint,
    jwt_check,
    misconfig,
    open_redirect,
    recon,
    secrets,
    takeover,
    webvuln,
)
from shaidra.utils.process import check_tools
from shaidra.utils.tool_install import ensure_on_path

StageCall = Callable[[ScanContext, EventBus], Awaitable[None]]

# Every external binary Shaidra knows how to drive. Missing entries are reported
# rather than treated as errors, so the pipeline degrades instead of aborting.
KNOWN_TOOLS: Final[tuple[str, ...]] = (
    "subfinder",
    "assetfinder",
    "httpx",
    "naabu",
    "katana",
    "nuclei",
    "dalfox",
    "sqlmap",
    "ffuf",
    "feroxbuster",
    "wpscan",
    "trufflehog",
    "testssl",
    "testssl.sh",
    "kiterunner",
    "kr",
    "gowitness",
    "wafw00f",
    "whatweb",
    "jwt_tool",
    "subjack",
    "gau",
    "waybackurls",
    "graphw00f",
)

# Stage 2, first wave: independent of crawl output.
_FIRST_WAVE: Final[tuple[tuple[str, Category, StageCall], ...]] = (
    ("Takeover", Category.TAKEOVER, takeover.run),
    ("Content discovery", Category.CONTENT, content_discovery.run),
    ("CORS", Category.CORS, cors.run),
    ("JWT", Category.JWT, jwt_check.run),
    ("API scan", Category.API, api_scan.run),
    ("CMS scan", Category.CMS, cms_scan.run),
    ("Misconfiguration", Category.MISCONFIG, misconfig.run),
    ("CVE match", Category.CVE, cve_match.run),
)

# Stage 2, second wave: these consume ctx.crawled_urls, so they wait for crawl.
_SECOND_WAVE: Final[tuple[tuple[str, Category, StageCall], ...]] = (
    ("Web vulnerabilities", Category.WEBVULN, webvuln.run),
    ("Open redirect", Category.REDIRECT, open_redirect.run),
    ("Secret scan", Category.SECRETS, secrets.run),
)


async def orchestrate(ctx: ScanContext, bus: EventBus) -> None:
    """Run the full pipeline, closing the event bus when finished."""
    ctx.start_time = time.monotonic()
    try:
        await _preflight(ctx, bus)
        await _recon(ctx, bus)
        await _scan(ctx, bus)
    finally:
        await bus.close()


async def _preflight(ctx: ScanContext, bus: EventBus) -> None:
    await bus.stage_start("Preflight")
    ensure_on_path()
    ctx.available_tools = check_tools(KNOWN_TOOLS)
    found = sorted(name for name, ok in ctx.available_tools.items() if ok)
    missing = sorted(name for name, ok in ctx.available_tools.items() if not ok)
    await bus.log(f"tools available: {len(found)}/{len(KNOWN_TOOLS)}")
    if missing:
        await bus.log(f"{len(missing)} tool(s) missing; install them with `shaidra --install-tools`")
    if ctx.verbose and missing:
        await bus.log(f"missing tools: {', '.join(missing)}")
    ctx.waf = await detect_waf(ctx, bus)
    if ctx.waf is not None:
        ctx.rate_limit = ctx.config.lowered_rate()
    await bus.stage_done("Preflight", f"{len(found)} tools")


async def _recon(ctx: ScanContext, bus: EventBus) -> None:
    await _guarded(recon.run, "Recon", ctx, bus)
    ctx.web_reachable = any(host.is_live for host in ctx.hosts.values())
    if not ctx.web_reachable:
        await bus.log("Target did not answer; probe stages will skip fast.", LogLevel.WARN)
    await _guarded(fingerprint.run, "Fingerprint", ctx, bus)


async def _scan(ctx: ScanContext, bus: EventBus) -> None:
    tasks: list[asyncio.Task[None]] = []
    if _crawl_requested(ctx.categories):
        tasks.append(asyncio.create_task(_guarded(crawl.run, "Crawl", ctx, bus)))
    port_scan = getattr(recon, "scan_ports", None)
    if callable(port_scan) and Category.RECON in ctx.categories:
        tasks.append(asyncio.create_task(_guarded(port_scan, "Port scan", ctx, bus)))
    for label, category, fn in _FIRST_WAVE:
        if category in ctx.categories:
            tasks.append(asyncio.create_task(_guarded(fn, label, ctx, bus)))
    if tasks:
        await asyncio.gather(*tasks)

    second: list[asyncio.Task[None]] = [
        asyncio.create_task(_guarded(fn, label, ctx, bus))
        for label, category, fn in _SECOND_WAVE
        if category in ctx.categories
    ]
    if second:
        await asyncio.gather(*second)

    if ctx.extended:
        await _screenshots(ctx, bus)


async def _screenshots(ctx: ScanContext, bus: EventBus) -> None:
    outdir = Path(ctx.config.reports_dir) / "screenshots"
    try:
        paths = await capture_screenshots(ctx, bus, outdir)
    except OSError as exc:
        await bus.log(f"screenshot capture failed: {exc}", LogLevel.WARN)
        return
    if paths:
        await bus.log(f"screenshots saved: {len(paths)}", LogLevel.SUCCESS)


async def _guarded(fn: StageCall, name: str, ctx: ScanContext, bus: EventBus) -> None:
    """Run a stage, converting any unexpected failure into a warning.

    Cancellation is deliberately not caught: asyncio.CancelledError derives from
    BaseException, so shutdown still propagates.
    """
    try:
        await fn(ctx, bus)
    except Exception as exc:  # noqa: BLE001 - supervisor boundary: one stage must never kill the scan
        await bus.stage_warn(name, f"unexpected error: {exc}")


def _crawl_requested(categories: set[Category]) -> bool:
    return bool(categories & {Category.WEBVULN, Category.REDIRECT, Category.SECRETS})
