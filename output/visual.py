"""Screenshot capture for the --extended flow, driven by gowitness.

The caller decides when this runs. Nothing is written to disk unless gowitness
is available and live host URLs exist; the output directory is created only
at that point, never implicitly elsewhere.
"""

from __future__ import annotations

import contextlib
import tempfile
from pathlib import Path
from typing import Final

from shaidra.core.events import EventBus
from shaidra.core.models import LogLevel, ScanContext
from shaidra.utils.process import RunOptions, run_tool, tool_available

_IMAGE_SUFFIXES: Final[frozenset[str]] = frozenset({".png", ".jpg", ".jpeg"})
_THREAD_CAP: Final[int] = 6


async def capture_screenshots(ctx: ScanContext, bus: EventBus, outdir: Path) -> list[Path]:
    """Screenshot every live host URL and return the image paths produced.

    gowitness exposes no requests-per-second flag, so throttling is a thread
    cap derived from ctx.rate_limit (never above gowitness's own default of
    six). Returns [] with a single bus log line when the tool is missing.
    """
    if not tool_available("gowitness"):
        await bus.log("gowitness not found on PATH; screenshots skipped.", LogLevel.WARN)
        return []
    urls = _live_urls(ctx)
    if not urls:
        await bus.log("No live host URLs to screenshot.", LogLevel.INFO)
        return []
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        await bus.log(f"Cannot create screenshot directory {outdir}: {exc}", LogLevel.WARN)
        return []
    before = _images_in(outdir)
    try:
        url_file = _write_urls(urls)
    except OSError as exc:
        await bus.log(f"Cannot write the temporary URL list: {exc}", LogLevel.WARN)
        return []
    threads = max(1, min(ctx.rate_limit, _THREAD_CAP))
    argv = [
        "gowitness",
        "scan",
        "file",
        "-f",
        str(url_file),
        "--screenshot-path",
        str(outdir),
        "--threads",
        str(threads),
    ]
    try:
        result = await run_tool(argv, RunOptions(timeout=float(ctx.config.timeout_for("gowitness"))))
    finally:
        with contextlib.suppress(OSError):
            url_file.unlink()
    if not result.ok:
        await bus.log(f"gowitness failed (rc={result.returncode}): {result.stderr.strip()[:300]}", LogLevel.WARN)
    produced = sorted(path for path in _images_in(outdir) if path not in before)
    if result.ok:
        await bus.log(f"{len(produced)} screenshot(s) saved to {outdir}.", LogLevel.SUCCESS)
    return produced


def _live_urls(ctx: ScanContext) -> list[str]:
    urls: list[str] = []
    for host in ctx.live_hosts():
        if host.url is not None:
            urls.append(host.url)
    return urls


def _write_urls(urls: list[str]) -> Path:
    """Write one URL per line to a temp file; caller owns the cleanup."""
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", suffix=".txt", prefix="shaidra_urls_", delete=False
    ) as handle:
        handle.write("\n".join(urls))
        handle.write("\n")
        return Path(handle.name)


def _images_in(outdir: Path) -> set[Path]:
    try:
        return {path for path in outdir.rglob("*") if path.suffix.lower() in _IMAGE_SUFFIXES}
    except OSError:
        return set()
