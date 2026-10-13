"""Live terminal rendering driven by the event bus.

A single consumer drains the bus while the scan runs. Stage lifecycle events
drive a progress panel; findings and status lines are printed the instant they
arrive, above the live region, so nothing is batched until the end.

When stdout is not a terminal (CI, piping, --quiet) the live region is skipped
and every event is printed sequentially instead.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, assert_never

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskID, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.style import Style
from rich.table import Column
from rich.text import Text

from shaidra.core.events import Event, EventBus, FindingEvent, HostEvent, LogEvent, StageEvent
from shaidra.core.models import Finding, Host, LogLevel, ScanContext, Severity, StageStatus
from shaidra.output import theme

_MARKERS: Final[dict[LogLevel, str]] = {
    LogLevel.INFO: "[*]",
    LogLevel.SUCCESS: "[+]",
    LogLevel.WARN: "[!]",
    LogLevel.ERROR: "[x]",
}
_STAGE_WIDTH: Final[int] = 18
_BAR_WIDTH: Final[int] = 28


class TerminalRenderer:
    """Consumes the event bus and renders the live view."""

    def __init__(self, console: Console, *, quiet: bool = False, verbose: bool = False) -> None:
        self._console = console
        self._quiet = quiet
        self._verbose = verbose
        self._progress = _build_progress(console)
        self._tasks: dict[str, TaskID] = {}
        self._live: Live | None = None
        self._live_enabled = (not quiet) and console.is_terminal

    def start(self) -> None:
        """Begin the live display if the terminal supports it."""
        if not self._live_enabled:
            return
        self._live = Live(self._render_live(), console=self._console, refresh_per_second=8, transient=False)
        self._live.start()

    def stop(self) -> None:
        """Tear down the live display."""
        if self._live is not None:
            self._live.stop()
            self._live = None

    async def consume(self, bus: EventBus, ctx: ScanContext) -> None:
        """Drain the bus until it is closed, handling each event in order."""
        while True:
            event = await bus.next_event()
            if event is None:
                return
            self._handle(event, ctx)

    def print_summary(self, ctx: ScanContext, duration: float, report_paths: Mapping[str, str] | None = None) -> None:
        """Print the closing severity summary and any report paths."""
        counts = _severity_counts(ctx.findings)
        self._console.print(Rule(style=theme.BRAND_PRIMARY))
        self._console.print(Text("SEVERITY SUMMARY", style=f"bold {theme.BRAND_ACCENT}"))
        self._console.print(_severity_line(counts))
        self._console.print(Rule(style=theme.BRAND_PRIMARY))
        self._console.print(_totals_line(ctx, duration))
        if report_paths:
            for label, path in report_paths.items():
                line = Text()
                line.append(f"{label} -> ", style=theme.muted_style())
                line.append(path, style=theme.accent_style())
                self._console.print(line)

    def _handle(self, event: Event, ctx: ScanContext) -> None:
        match event:
            case LogEvent(level=level, message=message):
                self._on_log(level, message)
            case FindingEvent(finding=finding):
                self._on_finding(finding, ctx)
            case StageEvent() as stage:
                self._on_stage(stage)
            case HostEvent(host=host):
                self._on_host(host)
            case unreachable:
                assert_never(unreachable)

    def _on_log(self, level: LogLevel, message: str) -> None:
        if self._quiet:
            return
        line = Text()
        line.append(_MARKERS[level], style=Style(color=theme.log_color(level), bold=True))
        line.append(f" {message}", style=theme.primary_style())
        self._console.print(line)

    def _on_finding(self, finding: Finding, ctx: ScanContext) -> None:
        ctx.findings.append(finding)
        if self._quiet:
            return
        self._console.print(_finding_block(finding, verbose=self._verbose))

    def _on_stage(self, stage: StageEvent) -> None:
        if not self._live_enabled:
            return
        match stage.status:
            case StageStatus.START:
                self._task(stage.name)
            case StageStatus.PROGRESS:
                self._set_progress(stage.name, stage.current, stage.total)
            case StageStatus.DONE | StageStatus.WARN | StageStatus.SKIP:
                self._complete(stage.name)
            case unreachable:
                assert_never(unreachable)

    def _on_host(self, host: Host) -> None:
        if self._quiet or not self._verbose:
            return
        self._console.print(Text(f"[*] host: {host.url or host.host}", style=theme.muted_style()))

    def _task(self, name: str) -> TaskID:
        existing = self._tasks.get(name)
        if existing is not None:
            return existing
        created = self._progress.add_task(name, total=100)
        self._tasks[name] = created
        return created

    def _set_progress(self, name: str, current: int, total: int) -> None:
        task = self._task(name)
        percent = (current / total * 100) if total else 0.0
        self._progress.update(task, completed=min(percent, 100.0))

    def _complete(self, name: str) -> None:
        self._progress.update(self._task(name), completed=100.0)

    def _render_live(self) -> RenderableType:
        panel = Panel(
            self._progress,
            title="SCAN STAGES",
            title_align="left",
            border_style=theme.BRAND_PRIMARY,
            padding=(0, 1),
        )
        return Group(panel)


def _build_progress(console: Console) -> Progress:
    return Progress(
        TextColumn("[progress.description]{task.description}", table_column=Column(width=_STAGE_WIDTH)),
        BarColumn(bar_width=_BAR_WIDTH, complete_style=theme.BRAND_PRIMARY, finished_style=theme.BRAND_ACCENT),
        TextColumn("{task.percentage:>3.0f}%", style=theme.BRAND_ACCENT),
        TimeElapsedColumn(),
        console=console,
        transient=False,
        expand=False,
    )


def _finding_block(finding: Finding, *, verbose: bool) -> Group:
    color = theme.severity_color(finding.severity)
    head = Text()
    head.append(f"[{finding.severity.value.upper()}] ", style=Style(color=color, bold=True))
    head.append(finding.host, style=theme.primary_style())
    title = Text("  └─ ")
    title.append(finding.title, style=Style(color=color))
    lines: list[Text] = [head, title]
    if finding.evidence:
        lines.append(_detail("evidence: ", finding.evidence))
    if verbose and finding.url:
        lines.append(_detail("url: ", finding.url))
    lines.append(_detail("tool: ", finding.tool))
    return Group(*lines)


def _detail(label: str, value: str) -> Text:
    line = Text("     ")
    line.append(label, style=theme.muted_style())
    line.append(value, style=theme.primary_style())
    return line


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts = dict.fromkeys(Severity, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def _severity_line(counts: dict[Severity, int]) -> Text:
    line = Text("  ")
    for severity in theme.SEVERITY_ORDER:
        count = counts[severity]
        if severity is Severity.UNKNOWN and count == 0:
            continue
        line.append(f"{severity.value.upper()} ", style=theme.severity_style(severity))
        line.append(f"{count}   ", style=theme.primary_style())
    return line


def _totals_line(ctx: ScanContext, duration: float) -> Text:
    line = Text()
    line.append(
        f"hosts: {len(ctx.hosts)}   live: {len(ctx.live_hosts())}   "
        f"findings: {len(ctx.findings)}   duration: {_format_duration(duration)}",
        style=theme.muted_style(),
    )
    return line


def _format_duration(seconds: float) -> str:
    total = int(seconds)
    minutes, secs = divmod(total, 60)
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"
