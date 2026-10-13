"""Command-line entry point for Shaidra.

Wires user options into a :class:`ScanContext`, starts the live renderer, runs
the orchestrated pipeline, then aggregates, reports, and summarises. By default
nothing is written to disk: reports are produced only when an ``-o`` format is
requested (``-oJ`` json, ``-oM`` markdown, ``-oT`` text, ``-oA`` all).
"""

from __future__ import annotations

import asyncio
import sys
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from shaidra import __version__
from shaidra.aggregator.dedup import dedup_findings
from shaidra.aggregator.severity import findings_by_severity
from shaidra.core.config import Config, load_config
from shaidra.core.events import EventBus
from shaidra.core.models import ALL_CATEGORIES, Category, ScanContext
from shaidra.core.orchestrator import KNOWN_TOOLS, orchestrate
from shaidra.core.scope import ScopeError, build_scope, parse_target
from shaidra.output.banner import render_banner
from shaidra.output.report import write_reports
from shaidra.output.terminal import TerminalRenderer
from shaidra.utils.tool_install import ensure_on_path, install_missing

_ERROR_STYLE = "red"


def _harden_streams() -> None:
    """Prevent encoding crashes when stdout/stderr are redirected.

    The banner and live view contain box-drawing and block glyphs that are not
    representable in the console codepage (cp1252 on most Windows systems).
    Redirected streams are switched to UTF-8; interactive terminals keep their
    native codepage, and unrepresentable characters are replaced instead of
    raising in both cases.
    """
    interactive = bool(getattr(sys.stdout, "isatty", lambda: False)())
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        kwargs: dict[str, str] = {"errors": "replace"}
        if not interactive:
            kwargs["encoding"] = "utf-8"
        try:
            reconfigure(**kwargs)
        except (ValueError, OSError):
            pass


def _make_console() -> Console:
    """Build a console that never uses Rich's legacy Windows renderer.

    When stdout is a pipe or file, Rich's legacy win32 path encodes through the
    console codepage and raises UnicodeEncodeError on the banner glyphs. A
    plain, uncolored console avoids that path entirely; interactive terminals
    keep Rich's default behavior.
    """
    interactive = bool(getattr(sys.stdout, "isatty", lambda: False)())
    if not interactive:
        return Console(legacy_windows=False, no_color=True)
    return Console()

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    help="Shaidra - deep web vulnerability scanner. Use only on assets you are authorized to test.",
)


def _version_callback(value: bool) -> None:
    """Print the version and exit before required arguments are validated."""
    if value:
        typer.echo(f"shaidra {__version__}")
        raise typer.Exit()


def _request_headers(cookie: str | None, headers: list[str]) -> dict[str, str]:
    """Merge the ``--cookie`` and repeatable ``--header`` values into one dict."""
    merged: dict[str, str] = {}
    if cookie:
        merged["Cookie"] = cookie
    for raw in headers:
        name, sep, value = raw.partition(":")
        if sep and name.strip():
            merged[name.strip()] = value.strip()
    return merged


def _prompt_target(console: Console) -> str:
    """Ask for a target interactively when none was given on the command line."""
    console.print("Enter the target to scan (host, host:port, or URL).", style="bright_black")
    while True:
        try:
            value = typer.prompt("Target")
        except (typer.Abort, EOFError, KeyboardInterrupt):
            console.print("\n[x] no target provided", style=_ERROR_STYLE, markup=False)
            raise typer.Exit(code=2) from None
        cleaned = value.strip()
        if cleaned:
            return cleaned
        console.print("[!] target cannot be empty", style="yellow", markup=False)


@app.command()
def main(
    target: Annotated[
        str | None,
        typer.Argument(help="Target host, host:port, or URL (authorized scope only). Prompted if omitted."),
    ] = None,
    scope: Annotated[str | None, typer.Option("--scope", "-s", help="Scope file: one domain, IP, or CIDR per line.")] = None,
    categories: Annotated[str | None, typer.Option("--categories", "-c", help="Comma-separated categories (default: all).")] = None,
    rate_limit: Annotated[int | None, typer.Option("--rate-limit", "-r", min=1, help="Requests per second (default: 40).")] = None,
    threads: Annotated[int | None, typer.Option("--threads", min=1, help="Concurrency for fuzzing tools.")] = None,
    mode: Annotated[str | None, typer.Option("--mode", "-m", help="Scan mode: quick or deep.")] = None,
    extended: Annotated[bool, typer.Option("--extended", "-x", help="Enable heavy checks (screenshots, full wordlists).")] = False,
    install_tools: Annotated[bool, typer.Option("--install-tools", help="Download and install missing external tools before scanning (or alone, without a target).")] = False,
    config_path: Annotated[str | None, typer.Option("--config", help="Path to a config.yaml file.")] = None,
    cookie: Annotated[str | None, typer.Option("--cookie", help="Session cookie sent with every request, e.g. \"session=abc123\".")] = None,
    header: Annotated[list[str], typer.Option("--header", "-H", help="Extra request header \"Name: value\" (repeatable).")] = [],
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show discovered hosts and extra detail.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress live output.")] = False,
    output: Annotated[list[str], typer.Option("-o", "--output", help="Report format(s): J, M, T, A (repeatable, e.g. -oJ -oA).")] = [],
    output_dir: Annotated[str | None, typer.Option("--output-dir", help="Directory for report files.")] = None,
    output_name: Annotated[str | None, typer.Option("--output-name", help="Base name for report files.")] = None,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show the version and exit."),
    ] = False,
) -> None:
    """Run a scan against TARGET and stream findings to the terminal."""
    _harden_streams()
    console = _make_console()

    if install_tools and not (target and target.strip()):
        asyncio.run(_install_only(console))
        raise typer.Exit()

    prompted = False
    raw_target = target.strip() if target else ""
    if not raw_target:
        prompted = True
        if not quiet:
            render_banner(console)
        raw_target = _prompt_target(console)

    selected = _parse_categories(categories)
    formats = _parse_output_formats(output)
    config = _apply_overrides(load_config(config_path), rate_limit=rate_limit, threads=threads, mode=mode)

    spec = parse_target(raw_target)
    try:
        effective_scope = build_scope(spec.host, scope)
    except ScopeError as exc:
        console.print(f"[x] {exc}", style=_ERROR_STYLE, markup=False)
        raise typer.Exit(code=2) from exc

    request_headers = _request_headers(cookie, header)

    ctx = ScanContext(
        target=spec.host_port,
        target_url=spec.url,
        mode=config.mode,
        categories=selected,
        rate_limit=config.rate_limit,
        extended=extended,
        scope=effective_scope,
        config=config,
        request_headers=request_headers,
        verbose=verbose,
        quiet=quiet,
        install_tools=install_tools,
    )

    if not quiet and not prompted:
        render_banner(console)

    outdir = Path(output_dir) if output_dir else Path(config.reports_dir)
    base_name = output_name or _default_base_name(spec.host_port)
    try:
        asyncio.run(_run_scan(ctx, console, formats=formats, outdir=outdir, base_name=base_name))
    except KeyboardInterrupt:
        console.print("[!] interrupted", style=_ERROR_STYLE, markup=False)
        raise typer.Exit(code=130) from None


async def _run_scan(ctx: ScanContext, console: Console, *, formats: set[str], outdir: Path, base_name: str) -> None:
    bus = EventBus()
    renderer = TerminalRenderer(console, quiet=ctx.quiet, verbose=ctx.verbose)
    renderer.start()
    consumer = asyncio.create_task(renderer.consume(bus, ctx))
    try:
        if ctx.install_tools:
            ensure_on_path()
            await install_missing(KNOWN_TOOLS, _bus_notify(bus))
        await orchestrate(ctx, bus)
    finally:
        await consumer
        renderer.stop()

    ctx.findings = findings_by_severity(dedup_findings(ctx.findings))
    duration = time.monotonic() - ctx.start_time
    report_paths = _write_reports(ctx, console, formats=formats, outdir=outdir, base_name=base_name)
    renderer.print_summary(ctx, duration, report_paths)


def _bus_notify(bus: EventBus):
    """Adapt the event bus into the installer's async ``notify`` callback."""

    async def notify(message: str) -> None:
        await bus.log(message)

    return notify


async def _install_only(console: Console) -> None:
    """Install missing tools without running a scan (``shaidra --install-tools``)."""
    ensure_on_path()

    async def notify(message: str) -> None:
        console.print(f"[*] {message}", markup=False, style="bright_black")

    await install_missing(KNOWN_TOOLS, notify)


def _write_reports(
    ctx: ScanContext,
    console: Console,
    *,
    formats: set[str],
    outdir: Path,
    base_name: str,
) -> dict[str, str]:
    if not formats:
        return {}
    try:
        paths = write_reports(ctx, formats, outdir, base_name)
    except OSError as exc:
        console.print(f"[x] failed to write reports: {exc}", style=_ERROR_STYLE, markup=False)
        return {}
    labels = {".json": "JSON", ".md": "Markdown", ".txt": "TXT"}
    return {labels.get(path.suffix, path.suffix.lstrip(".").upper()): str(path) for path in paths}


def _apply_overrides(config: Config, *, rate_limit: int | None, threads: int | None, mode: str | None) -> Config:
    changes: dict[str, int | str] = {}
    if rate_limit is not None:
        changes["rate_limit"] = rate_limit
    if threads is not None:
        changes["ffuf_threads"] = threads
    if mode is not None:
        changes["mode"] = mode.lower()
    return replace(config, **changes) if changes else config


def _parse_categories(raw: str | None) -> set[Category]:
    if raw is None or not raw.strip():
        return set(ALL_CATEGORIES)
    selected: set[Category] = set()
    for token in raw.split(","):
        name = token.strip().lower()
        if not name:
            continue
        try:
            selected.add(Category(name))
        except ValueError as exc:
            raise typer.BadParameter(f"unknown category: {name}") from exc
    return selected or set(ALL_CATEGORIES)


def _parse_output_formats(values: list[str]) -> set[str]:
    formats: set[str] = set()
    for raw in values:
        for token in raw.split(","):
            code = token.strip().lower()
            match code:
                case "":
                    continue
                case "j" | "json":
                    formats.add("json")
                case "m" | "md" | "markdown":
                    formats.add("markdown")
                case "t" | "txt" | "text":
                    formats.add("txt")
                case "a" | "all":
                    formats.update({"json", "markdown", "txt"})
                case _:
                    raise typer.BadParameter(f"unknown report format: {token}")
    return formats


def _default_base_name(target: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in target)
    return f"shaidra_{safe}_{stamp}"
