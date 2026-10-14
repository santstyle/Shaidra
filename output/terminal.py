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

from rich import box
from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TaskID, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.style import Style
from rich.table import Column, Table
from rich.text import Text

from shaidra.core.events import Event, EventBus, FindingEvent, HostEvent, LogEvent, StageEvent
from shaidra.core.models import Finding, Host, LogLevel, ScanContext, Severity, StageStatus
from shaidra.output import theme
from shaidra.output.dashboard import (
    MIN_DASHBOARD_HEIGHT,
    MIN_DASHBOARD_WIDTH,
    DashboardState,
    LiveRebuild,
    build_dashboard,
)

_MARKERS: Final[dict[LogLevel, str]] = {
    LogLevel.INFO: "[*]",
    LogLevel.SUCCESS: "[+]",
    LogLevel.WARN: "[!]",
    LogLevel.ERROR: "[x]",
}
_STAGE_WIDTH: Final[int] = 18
_BAR_WIDTH: Final[int] = 28
_MAX_TABLE_ROWS: Final[int] = 25


class TerminalRenderer:
    """Consumes the event bus and renders the live view.

    Interactive terminals wide enough for it get the full-screen dashboard;
    everywhere else (pipes, CI, --quiet, tiny windows) falls back to a single
    progress panel with directly printed log lines.
    """

    def __init__(
        self,
        console: Console,
        *,
        quiet: bool = False,
        verbose: bool = False,
        scope_file: str | None = None,
        formats: set[str] | frozenset[str] | None = None,
        report_dir: str | None = None,
    ) -> None:
        self._console = console
        self._quiet = quiet
        self._verbose = verbose
        self._scope_file = scope_file
        self._formats = frozenset(formats or ())
        self._report_dir = report_dir
        self._progress = _build_progress(console)
        self._tasks: dict[str, TaskID] = {}
        self._live: Live | None = None
        self._state: DashboardState | None = None
        self._live_enabled = (not quiet) and console.is_terminal
        self._dashboard_enabled = (
            self._live_enabled and console.width >= MIN_DASHBOARD_WIDTH and console.height >= MIN_DASHBOARD_HEIGHT
        )

    def start(self, ctx: ScanContext | None = None) -> None:
        """Begin the live display if the terminal supports it."""
        if not self._live_enabled:
            return
        renderable: RenderableType
        if self._dashboard_enabled and ctx is not None:
            self._state = DashboardState(
                ctx=ctx,
                scope_file=self._scope_file,
                formats=self._formats,
                report_dir=self._report_dir,
            )
            renderable = LiveRebuild(lambda: build_dashboard(self._state))
        else:
            renderable = self._render_live()
        # 4 Hz is smooth enough for stage ticks without the double-paint
        # flicker that 8 Hz causes on Windows conhost.
        self._live = Live(renderable, console=self._console, refresh_per_second=4, transient=False)
        self._live.start()

    def stop(self) -> None:
        """Tear down the live display."""
        if self._live is not None:
            if self._state is not None:
                self._state.finished = True
                self._live.update(LiveRebuild(lambda: build_dashboard(self._state)), refresh=True)
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
        """Print the closing summary: counts, a scannable findings table, and report paths."""
        findings = ctx.findings
        counts = _severity_counts(findings)
        self._console.print()
        self._console.print(Rule(style=theme.BRAND_PRIMARY))
        self._console.print(_headline(len(findings), duration))
        self._console.print(_severity_line(counts))
        self._console.print(Rule(style=theme.BRAND_PRIMARY))
        if findings:
            self._console.print(_findings_table(findings))
        else:
            self._console.print(Text("  No findings. Target looks clean.", style=theme.muted_style()))
        self._console.print(_totals_line(ctx))
        if report_paths:
            for label, path in report_paths.items():
                line = Text("  ")
                line.append(f"{label} -> ", style=theme.muted_style())
                line.append(path, style=theme.accent_style())
                self._console.print(line)
        self._console.print(Rule(style=theme.BRAND_PRIMARY))

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
        if self._state is not None:
            self._state.on_log(level, message)
            return
        line = Text()
        line.append(_MARKERS[level], style=Style(color=theme.log_color(level), bold=True))
        line.append(f" {message}", style=theme.primary_style())
        self._console.print(line)

    def _on_finding(self, finding: Finding, ctx: ScanContext) -> None:
        ctx.findings.append(finding)
        if self._quiet:
            return
        if self._state is not None:
            self._state.on_finding(finding)
            return
        self._console.print()
        self._console.print(_finding_block(finding))

    def _on_stage(self, stage: StageEvent) -> None:
        if self._state is not None:
            self._state.on_stage(stage)
            return
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
        if self._state is not None:
            self._state.on_host(host)
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


def _finding_block(finding: Finding) -> Group:
    color = theme.severity_color(finding.severity)
    head = Text()
    head.append("  ")
    head.append("● ", style=Style(color=color, bold=True))
    head.append(f"{finding.severity.value.upper():<8} ", style=Style(color=color, bold=True))
    head.append(finding.title, style=Style(bold=True))
    lines: list[Text] = [head]
    lines.append(_detail("where", finding.url or finding.host))
    if finding.evidence:
        lines.append(_detail("proof", finding.evidence))
    lines.append(_detail("tool", finding.tool))
    return Group(*lines)


def _detail(label: str, value: str) -> Text:
    line = Text("        ")
    line.append(f"{label:<7}", style=theme.muted_style())
    line.append(value, style=theme.primary_style())
    return line


def _headline(count: int, duration: float) -> Text:
    line = Text("  ")
    line.append("SCAN COMPLETE", style=f"bold {theme.BRAND_ACCENT}")
    line.append("   ")
    line.append(f"{count} finding(s)", style=theme.primary_style())
    line.append("   ")
    line.append(_format_duration(duration), style=theme.muted_style())
    return line


def _findings_table(findings: list[Finding]) -> Table:
    table = Table(box=box.SIMPLE_HEAD, show_edge=False, pad_edge=False, expand=False, padding=(0, 1))
    table.add_column("SEVERITY", no_wrap=True)
    table.add_column("FINDING", overflow="fold")
    table.add_column("HOST", no_wrap=True)
    shown = findings[:_MAX_TABLE_ROWS]
    for finding in shown:
        table.add_row(
            Text(finding.severity.value.upper(), style=theme.severity_style(finding.severity)),
            Text(finding.title, style=theme.primary_style()),
            Text(finding.host, style=theme.muted_style()),
        )
    hidden = len(findings) - len(shown)
    if hidden > 0:
        table.add_row(
            Text(""),
            Text(f"+{hidden} more (see report)", style=theme.muted_style()),
            Text(""),
        )
    return table


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


def _totals_line(ctx: ScanContext) -> Text:
    line = Text("  ")
    line.append(
        f"hosts: {len(ctx.hosts)}   live: {len(ctx.live_hosts())}   findings: {len(ctx.findings)}",
        style=theme.muted_style(),
    )
    return line


def _format_duration(seconds: float) -> str:
    total = int(seconds)
    minutes, secs = divmod(total, 60)
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"
