"""Full-screen Textual live-scan dashboard for Shaidra."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Set as AbstractSet
from datetime import datetime
from pathlib import Path
from typing import ClassVar

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, RichLog, Static

from shaidra import __version__
from shaidra.aggregator.dedup import dedup_findings
from shaidra.aggregator.severity import findings_by_severity
from shaidra.core.events import (
    EventBus,
    FindingEvent,
    HostEvent,
    LogEvent,
    StageEvent,
)
from shaidra.core.models import (
    ALL_CATEGORIES,
    Finding,
    Host,
    LogLevel,
    ScanContext,
    Severity,
    StageStatus,
)
from shaidra.core.orchestrator import KNOWN_TOOLS, orchestrate
from shaidra.output import theme
from shaidra.output.banner import logo_art_text_sampled
from shaidra.output.dashboard import DashboardState
from shaidra.output.report import write_reports
from shaidra.utils import stats
from shaidra.utils.tool_install import ensure_on_path, install_missing

# ── bus events → UI messages ──────────────────────────────────────────


class StageMsg(Message):
    def __init__(self, stage: StageEvent) -> None:
        super().__init__()
        self.stage = stage


class LogMsg(Message):
    def __init__(self, level: LogLevel, message: str) -> None:
        super().__init__()
        self.level = level
        self.message = message


class FindingMsg(Message):
    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding


class HostMsg(Message):
    def __init__(self, host: Host) -> None:
        super().__init__()
        self.host = host


class ScanCompleteMsg(Message):
    def __init__(self, duration: float, report_paths: dict[str, str]) -> None:
        super().__init__()
        self.duration = duration
        self.report_paths = report_paths


# ── helpers ────────────────────────────────────────────────────────────

_SEV_COLOR = {
    severity: theme.DASH_SEVERITY_COLORS[severity] for severity in Severity
}

_LOG_LEVEL_COLORS = {
    LogLevel.INFO: theme.DASH_TEXT,
    LogLevel.SUCCESS: theme.DASH_OK,
    LogLevel.WARN: "#FBBF24",
    LogLevel.ERROR: theme.DASH_SEVERITY_COLORS[Severity.CRITICAL],
}

_BAR_WIDTH = 14


def _bar_text(percent: float, *, done: bool = False) -> Text:
    """Fixed-width block bar; done bars use the brighter accent."""
    filled = max(0, min(_BAR_WIDTH, round(percent / 100.0 * _BAR_WIDTH)))
    text = Text()
    text.append("█" * filled, style=theme.DASH_ACCENT_BRIGHT if done else theme.DASH_ACCENT)
    text.append("█" * (_BAR_WIDTH - filled), style=theme.DASH_BAR_TRACK)
    return text


def _progress_row(label: str, percent: float, *, done: bool, dim: bool = False) -> Text:
    """One progress line: label, bar, percent."""
    text = Text()
    text.append(f"{label:<12}", style=theme.DASH_DIM if dim else theme.DASH_TEXT)
    if dim:
        text.append("█" * _BAR_WIDTH, style=theme.DASH_BAR_TRACK)
        text.append("  —", style=theme.DASH_DIM)
        return text
    text.append(" ")
    text.append(_bar_text(percent, done=done))
    text.append(f" {percent:4.0f}%", style=theme.DASH_ACCENT_BRIGHT if done else theme.DASH_DIM)
    if done:
        text.append(" ✓", style=theme.DASH_OK)
    return text


def _join_lines(parts: list[Text]) -> Text:
    out = Text()
    for index, part in enumerate(parts):
        if index:
            out.append("\n")
        out.append_text(part)
    return out


def _header_info(ctx: ScanContext) -> Text:
    total = len(ALL_CATEGORIES)
    selected = len(ctx.categories)
    cats = f"All ({total})" if selected >= total else f"{selected} of {total}"
    text = Text()
    text.append("Target   ", style=theme.DASH_DIM)
    text.append(ctx.target_url, style=theme.DASH_ACCENT_BRIGHT)
    text.append("\n")
    text.append("Mode     ", style=theme.DASH_DIM)
    text.append(ctx.mode, style=theme.DASH_ACCENT)
    text.append("  ·  Rate ", style=theme.DASH_DIM)
    text.append(f"{ctx.rate_limit} req/s", style=theme.DASH_ACCENT)
    text.append("  ·  Categories ", style=theme.DASH_DIM)
    text.append(cats, style=theme.DASH_ACCENT)
    text.append("\n")
    text.append(f"v{__version__}", style=theme.DASH_DIM)
    text.append("  ·  authorized targets only", style=theme.DASH_DIM)
    return text


def _timestamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ── summary screen ─────────────────────────────────────────────────────


class SummaryScreen(ModalScreen[None]):
    """Full findings table with complete URLs; same dark-purple chrome as the dashboard."""

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("escape", "dismiss_screen", "Close"),
        Binding("q", "dismiss_screen", "Close", show=False),
    ]

    CSS = """
    SummaryScreen {
        align: center middle;
        background: #0B0713ee;
    }
    #summary-panel {
        width: 94%;
        height: 92%;
        border: solid #4C1D95;
        background: #120C20;
        padding: 1 2;
    }
    #summary-headline {
        height: auto;
        padding-bottom: 1;
    }
    #summary-table {
        height: 1fr;
        scrollbar-color: #4C1D95;
    }
    """

    def __init__(
        self,
        findings: list[Finding],
        *,
        duration: float = 0.0,
        report_paths: dict[str, str] | None = None,
    ) -> None:
        super().__init__()
        self._findings = findings
        self._duration = duration
        self._report_paths = report_paths or {}

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="summary-panel"):
            yield Static(self._headline(), id="summary-headline")
            yield Static(self._severity_line())
            if self._report_paths:
                yield Static(self._reports_line())
            yield Static("")
            yield DataTable(id="summary-table")

    def on_mount(self) -> None:
        table = self.query_one("#summary-table", DataTable)
        table.add_columns("SEVERITY", "FINDING", "URL", "TOOL")
        table.cursor_type = "row"
        for finding in self._findings:
            table.add_row(
                Text(finding.severity.name, style=_SEV_COLOR[finding.severity]),
                finding.title,
                finding.url or finding.host or "-",
                finding.tool or "-",
            )

    def _headline(self) -> Text:
        text = Text()
        text.append("SCAN COMPLETE", style=f"bold {theme.DASH_ACCENT_BRIGHT}")
        if self._duration:
            text.append(f"  ·  {self._duration:.1f}s", style=theme.DASH_DIM)
        text.append(f"  ·  {len(self._findings)} finding(s)", style=theme.DASH_ACCENT)
        text.append("\n")
        text.append(
            "Scroll the table for full URLs · Esc/q to close",
            style=theme.DASH_DIM,
        )
        return text

    def _severity_line(self) -> Text:
        counts = dict.fromkeys(Severity, 0)
        for finding in self._findings:
            counts[finding.severity] += 1
        text = Text()
        for severity in theme.SEVERITY_ORDER:
            if not counts[severity]:
                continue
            text.append(f"{severity.name} ", style=f"bold {_SEV_COLOR[severity]}")
            text.append(f"{counts[severity]}   ", style=theme.DASH_TEXT)
        return text

    def _reports_line(self) -> Text:
        text = Text()
        text.append("Reports: ", style=theme.DASH_DIM)
        for index, (fmt, path) in enumerate(self._report_paths.items()):
            if index:
                text.append("  ·  ", style=theme.DASH_DIM)
            text.append(fmt, style=theme.DASH_OK)
            text.append(f" {path}", style=theme.DASH_TEXT)
        return text

    def action_dismiss_screen(self) -> None:
        self.dismiss()


# ── main app ───────────────────────────────────────────────────────────


class ShaidraApp(App[None]):
    """htop-style full-screen dashboard: logo header, progress, live feed, findings."""

    CSS = """
    Screen {
        background: #0B0713;
        color: #E6E1F2;
    }
    #header {
        height: auto;
        background: #120C20;
        border-bottom: solid #4C1D95;
        padding: 0 1;
    }
    #logo {
        width: auto;
        margin-right: 2;
    }
    #header-info {
        width: 1fr;
        height: auto;
        padding-top: 1;
    }
    #main {
        height: 1fr;
    }
    .panel {
        background: #120C20;
        border: solid #4C1D95;
        padding: 0 1;
    }
    .panel-title {
        color: #A78BFA;
        text-style: bold;
        background: #120C20;
    }
    #left {
        width: 28%;
    }
    #center {
        width: 40%;
    }
    #right {
        width: 32%;
    }
    #progress, #stats, #summary {
        height: auto;
    }
    #feed, #findings {
        height: 1fr;
        scrollbar-color: #4C1D95;
    }
    #status {
        height: auto;
    }
    """

    BINDINGS: ClassVar[list[Binding]] = [
        Binding("q", "quit", "Quit"),
        Binding("ctrl+c", "quit", "Quit", priority=True),
        Binding("s", "show_summary", "Summary"),
    ]

    def __init__(
        self,
        ctx: ScanContext,
        *,
        formats: AbstractSet[str],
        outdir: Path,
        base_name: str,
        scope_file: str | None = None,
    ) -> None:
        super().__init__()
        self.ctx = ctx
        self.formats = frozenset(formats)
        self.outdir = outdir
        self.base_name = base_name
        self.scope_file = scope_file
        self.state = DashboardState(
            ctx=ctx,
            scope_file=scope_file,
            formats=frozenset(formats),
            report_dir=str(outdir),
        )
        self._finished = False
        self._report_paths: dict[str, str] = {}

    # ── compose ────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        with Horizontal(id="header"):
            yield Static(logo_art_text_sampled(5), id="logo")
            yield Static(_header_info(self.ctx), id="header-info")
        with Horizontal(id="main"):
            with Vertical(id="left", classes="panel"):
                yield Static("SCAN PROGRESS", classes="panel-title")
                yield Static("", id="progress")
                yield Static("LIVE STATS", classes="panel-title")
                yield Static("", id="stats")
            with Vertical(id="center", classes="panel"):
                yield Static("LIVE SCAN", classes="panel-title")
                yield RichLog(id="feed", wrap=False, highlight=False, markup=False)
                yield Static("", id="status")
            with Vertical(id="right", classes="panel"):
                yield Static("FINDINGS SUMMARY", classes="panel-title")
                yield Static("", id="summary")
                yield Static("ALL FINDINGS · scroll for full URLs", classes="panel-title")
                yield DataTable(id="findings")
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Shaidra"
        self.sub_title = self.ctx.target
        findings = self.query_one("#findings", DataTable)
        findings.add_columns("SEV", "FINDING", "URL")
        findings.cursor_type = "row"
        self._refresh_progress()
        self._refresh_stats()
        self._refresh_summary()
        self._refresh_status()
        self._run_scan()

    # ── scan worker ────────────────────────────────────────────────────

    @work(exclusive=True, group="scan")
    async def _run_scan(self) -> None:
        bus = EventBus()
        consumer = asyncio.create_task(self._consume(bus))
        try:
            if self.ctx.install_tools:
                ensure_on_path()
                await install_missing(KNOWN_TOOLS, _bus_notify(bus))
            await orchestrate(self.ctx, bus)
        finally:
            # orchestrate closes the bus on its own; this second close is a
            # no-op unless install_missing raised before orchestrate ran.
            await bus.close()
            await consumer

        self.ctx.findings = findings_by_severity(dedup_findings(self.ctx.findings))
        duration = time.monotonic() - self.ctx.start_time if self.ctx.start_time else 0.0
        self._report_paths = self._write_reports()
        self._finished = True
        self.state.finished = True
        self._refresh_progress()
        self._refresh_stats()
        self._refresh_summary()
        self.post_message(ScanCompleteMsg(duration=duration, report_paths=self._report_paths))

    async def _consume(self, bus: EventBus) -> None:
        while True:
            event = await bus.next_event()
            if event is None:
                return
            self._dispatch(event)

    def _dispatch(self, event: object) -> None:
        if isinstance(event, StageEvent):
            self.state.on_stage(event)
            self.post_message(StageMsg(event))
        elif isinstance(event, LogEvent):
            self.state.on_log(event.level, event.message)
            self.post_message(LogMsg(event.level, event.message))
        elif isinstance(event, FindingEvent):
            self.ctx.findings.append(event.finding)
            self.state.on_finding(event.finding)
            self.post_message(FindingMsg(event.finding))
        elif isinstance(event, HostEvent):
            if self.ctx.verbose:
                self.state.on_host(event.host)
                self.post_message(HostMsg(event.host))

    def _write_reports(self) -> dict[str, str]:
        if not self.formats:
            return {}
        try:
            paths = write_reports(self.ctx, self.formats, self.outdir, self.base_name)
        except OSError as exc:
            self.notify(f"Failed to write reports: {exc}", severity="error")
            return {}
        labels = {".json": "JSON", ".md": "Markdown", ".txt": "TXT"}
        return {
            labels.get(path.suffix, path.suffix.lstrip(".").upper()): str(path)
            for path in paths
        }

    # ── message handlers ───────────────────────────────────────────────

    def on_stage_msg(self, msg: StageMsg) -> None:
        self._refresh_progress()
        self._refresh_status()
        tag, color = self.state.current_tag()
        line = Text()
        line.append(f"[{_timestamp()}] ", style=theme.DASH_DIM)
        line.append(f"[{tag}] ", style=f"bold {color}")
        line.append(f"{msg.stage.name} → {msg.stage.status.value}", style=theme.DASH_TEXT)
        if msg.stage.detail and msg.stage.status is not StageStatus.PROGRESS:
            line.append(f"  {msg.stage.detail}", style=theme.DASH_DIM)
        self.query_one("#feed", RichLog).write(line)

    def on_log_msg(self, msg: LogMsg) -> None:
        tag, color = self.state.current_tag()
        line = Text()
        line.append(f"[{_timestamp()}] ", style=theme.DASH_DIM)
        line.append(f"[{tag}] ", style=f"bold {color}")
        line.append(msg.message, style=_LOG_LEVEL_COLORS.get(msg.level, theme.DASH_TEXT))
        self.query_one("#feed", RichLog).write(line)
        self._refresh_status()

    def on_finding_msg(self, msg: FindingMsg) -> None:
        finding = msg.finding
        url = finding.url or finding.host or "-"

        tag, _ = self.state.current_tag()
        line = Text()
        line.append(f"[{_timestamp()}] ", style=theme.DASH_DIM)
        line.append(f"[{tag}] ", style=f"bold {theme.DASH_ACCENT}")
        line.append(f"{finding.severity.name} ", style=f"bold {_SEV_COLOR[finding.severity]}")
        line.append(finding.title, style=theme.DASH_TEXT)
        if url != "-":
            line.append(f"  →  {url}", style=theme.DASH_ACCENT_BRIGHT)
        self.query_one("#feed", RichLog).write(line)

        table = self.query_one("#findings", DataTable)
        table.add_row(
            Text(finding.severity.name, style=_SEV_COLOR[finding.severity]),
            finding.title,
            url,
        )
        self._refresh_summary()
        self._refresh_stats()

    def on_host_msg(self, msg: HostMsg) -> None:
        host = msg.host
        line = Text()
        line.append(f"[{_timestamp()}] ", style=theme.DASH_DIM)
        line.append("[host] ", style=f"bold {theme.DASH_DIM}")
        line.append(host.url or host.host, style=theme.DASH_TEXT)
        if host.status_code is not None:
            line.append(f"  {host.status_code}", style=theme.DASH_ACCENT)
        if host.title:
            line.append(f"  {host.title}", style=theme.DASH_DIM)
        self.query_one("#feed", RichLog).write(line)

    def on_scan_complete_msg(self, msg: ScanCompleteMsg) -> None:
        status = self.query_one("#status", Static)
        text = Text()
        text.append("✓ SCAN COMPLETE", style=f"bold {theme.DASH_OK}")
        text.append(f"  {len(self.ctx.findings)} finding(s)", style=theme.DASH_ACCENT)
        if msg.duration:
            text.append(f"  ·  {msg.duration:.1f}s", style=theme.DASH_DIM)
        if msg.report_paths:
            text.append("  ·  reports written", style=theme.DASH_OK)
        text.append("\n")
        text.append("press ", style=theme.DASH_DIM)
        text.append("s", style=f"bold {theme.DASH_ACCENT_BRIGHT}")
        text.append(" for summary · ", style=theme.DASH_DIM)
        text.append("q", style=f"bold {theme.DASH_ACCENT_BRIGHT}")
        text.append(" to quit", style=theme.DASH_DIM)
        status.update(text)
        self.push_screen(
            SummaryScreen(
                list(self.ctx.findings),
                duration=msg.duration,
                report_paths=msg.report_paths,
            )
        )

    # ── refresh helpers ────────────────────────────────────────────────

    def _refresh_progress(self) -> None:
        lines: list[Text] = []
        overall = 100.0 if self._finished else self.state.overall()
        lines.append(_progress_row("Overall", overall, done=self._finished))
        for row_key, selected in self.state.display_rows():
            if not selected:
                lines.append(_progress_row(row_key, 0.0, done=False, dim=True))
                continue
            percent = self.state.row_percent(row_key)
            done = self.state.row_state(row_key) == "done"
            lines.append(_progress_row(row_key, percent, done=done))
        self.query_one("#progress", Static).update(_join_lines(lines))

    def _refresh_stats(self) -> None:
        ctx = self.ctx
        rows = [
            ("Hosts", str(len(ctx.hosts))),
            ("URLs", str(len(ctx.crawled_urls))),
            ("Forms", str(len(ctx.form_targets))),
            ("Requests", str(stats.request_count())),
            ("Avg latency", f"{stats.average_ms():.0f} ms"),
            ("Findings", str(len(ctx.findings))),
        ]
        text = Text()
        for label, value in rows:
            text.append(f"  {label:<12}", style=theme.DASH_DIM)
            text.append(f"{value}\n", style=theme.DASH_ACCENT_BRIGHT)
        self.query_one("#stats", Static).update(text)

    def _refresh_summary(self) -> None:
        counts = dict.fromkeys(Severity, 0)
        for finding in self.ctx.findings:
            counts[finding.severity] += 1
        total = len(self.ctx.findings)
        text = Text()
        text.append("  Total  ", style=theme.DASH_TITLE)
        text.append(f"{total}\n", style=theme.DASH_ACCENT_BRIGHT)
        for severity in theme.SEVERITY_ORDER:
            if not counts[severity]:
                continue
            text.append(f"  {severity.name:<10}", style=f"bold {_SEV_COLOR[severity]}")
            text.append(f"{counts[severity]}\n", style=theme.DASH_TEXT)
        if not total:
            text.append("  (none yet)\n", style=theme.DASH_DIM)
        self.query_one("#summary", Static).update(text)

    def _refresh_status(self) -> None:
        if self._finished:
            return
        status = self.query_one("#status", Static)
        text = Text()
        tag, color = self.state.current_tag()
        text.append(f"  {tag}", style=f"bold {color}")
        text.append(f"  {self.state._last_stage or 'waiting…'}", style=theme.DASH_TEXT)
        if self.ctx.verbose:
            text.append(
                f"  ·  {len(self.ctx.hosts)} hosts  {len(self.ctx.crawled_urls)} urls",
                style=theme.DASH_DIM,
            )
        status.update(text)

    # ── actions ────────────────────────────────────────────────────────

    def action_show_summary(self) -> None:
        duration = time.monotonic() - self.ctx.start_time if self.ctx.start_time else 0.0
        self.push_screen(
            SummaryScreen(
                list(self.ctx.findings),
                duration=duration,
                report_paths=dict(self._report_paths),
            )
        )


def _bus_notify(bus: EventBus):
    """Adapt the event bus into the installer's async notify callback."""

    async def notify(message: str) -> None:
        await bus.log(message)

    return notify
