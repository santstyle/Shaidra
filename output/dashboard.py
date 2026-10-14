"""Full-screen dark-purple dashboard renderables for the live scan view.

The dashboard is only built for real interactive terminals wide and tall
enough to hold its three columns; everywhere else (pipes, CI, --quiet, tiny
windows) the renderer falls back to the simple progress panel so output stays
readable and machine-friendly. Builders here are pure over
:class:`DashboardState` except the two time/counter-backed panels, which are
wrapped in :class:`LiveRebuild` so Rich re-invokes them on every refresh pass.
"""

from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final

from rich import box
from rich.align import Align
from rich.console import Group, RenderableType
from rich.layout import Layout
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text

from shaidra import __version__
from shaidra.core.events import StageEvent
from shaidra.core.models import ALL_CATEGORIES, Category, Finding, Host, LogLevel, ScanContext, Severity, StageStatus
from shaidra.output import theme
from shaidra.output.banner import banner_text
from shaidra.utils import stats

MIN_DASHBOARD_WIDTH: Final[int] = 120
MIN_DASHBOARD_HEIGHT: Final[int] = 24

_FEED_MAX: Final[int] = 250
_BAR_WIDTH: Final[int] = 14
_CONFIG_LABEL_WIDTH: Final[int] = 12
_STATS_LABEL_WIDTH: Final[int] = 18

_HMS: Final[str] = "%H:%M:%S"

# Display order for the progress rows; crawl is not a Category but a stage the
# list always shows when the pipeline will actually run it.
_ROW_ORDER: Final[tuple[str, ...]] = (
    "recon",
    "crawl",
    "content",
    "api",
    "cms",
    "webvuln",
    "redirect",
    "takeover",
    "cve",
    "secrets",
    "cors",
    "jwt",
    "misconfig",
)

# One progress row aggregates every bus stage name that contributes to it, so
# sequential phases (recon then fingerprint then port-scan) read as one bar.
# Names must match the STAGE / STAGE_NAME constants the stages actually emit
# on the bus — any drift silently freezes that row at 0%.
_ROW_MEMBERS: Final[dict[str, tuple[str, ...]]] = {
    "recon": ("recon", "fingerprint", "port-scan"),
    "crawl": ("Crawl",),
    "content": ("Content discovery",),
    "api": ("API scan",),
    "cms": ("CMS scan",),
    "webvuln": ("Web vulns",),
    "redirect": ("open_redirect",),
    "takeover": ("Takeover detection",),
    "cve": ("CVE matching",),
    "secrets": ("Secret scan",),
    "cors": ("cors",),
    "jwt": ("JWT",),
    "misconfig": ("Misconfiguration",),
}

_STAGE_TO_ROW: Final[dict[str, str]] = {stage: row for row, stages in _ROW_MEMBERS.items() for stage in stages}

# Stage-tag colors stay inside the violet/blue/cyan/amber family; pink and
# magenta are excluded by explicit user constraint.
_TAG_COLORS: Final[dict[str, str]] = {
    "recon": "#22D3EE",
    "crawl": "#A78BFA",
    "content": "#FBBF24",
    "api": "#60A5FA",
    "cms": "#818CF8",
    "webvuln": "#A855F7",
    "redirect": "#C4B5FD",
    "takeover": "#38BDF8",
    "cve": "#3B82F6",
    "secrets": "#F59E0B",
    "cors": "#93C5FD",
    "jwt": "#67E8F9",
    "misconfig": "#FCD34D",
    "scan": theme.DASH_DIM,
}

_LOG_LEVEL_COLORS: Final[dict[LogLevel, str]] = {
    LogLevel.INFO: theme.DASH_TEXT,
    LogLevel.SUCCESS: theme.DASH_OK,
    LogLevel.WARN: "#FBBF24",
    LogLevel.ERROR: theme.DASH_SEVERITY_COLORS[Severity.CRITICAL],
}

_DOT_COLORS: Final[dict[str, str]] = {
    "done": theme.DASH_OK,
    "active": theme.DASH_ACCENT,
    "queued": theme.DASH_DIM,
}

_FORMAT_ORDER: Final[tuple[str, ...]] = ("json", "markdown", "txt")
_FORMAT_LABELS: Final[dict[str, str]] = {"json": "JSON", "markdown": "Markdown", "txt": "TXT"}

_SEVERITY_SLICE_ORDER: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
)

_ROW_SEVERITIES: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
)

_DONUT_W: Final[int] = 21
_DONUT_H: Final[int] = 11
_DONUT_INNER: Final[float] = 0.45
_DONUT_OUTER: Final[float] = 1.02

_RECENT_MAX: Final[int] = 8


class LiveRebuild:
    """Re-invokes its builder on every render pass.

    Values that change without a bus event (the elapsed clock, request
    counters incremented by httpx hooks) would freeze between events if held
    as a static renderable, so those panels wrap themselves in this.
    """

    __slots__ = ("_builder",)

    def __init__(self, builder: Callable[[], RenderableType]) -> None:
        self._builder = builder

    def __rich__(self) -> RenderableType:
        return self._builder()


@dataclass(slots=True)
class DashboardState:
    """Mutable view-model the dashboard renderables read on every pass."""

    ctx: ScanContext
    scope_file: str | None = None
    formats: frozenset[str] = frozenset()
    report_dir: str | None = None
    stage_status: dict[str, StageStatus] = field(default_factory=dict)
    stage_percent: dict[str, float] = field(default_factory=dict)
    feed: deque[Text] = field(default_factory=lambda: deque(maxlen=_FEED_MAX))
    finished: bool = False
    _last_stage: str = ""

    def current_tag(self) -> tuple[str, str]:
        """Return the (uppercase tag, color) for the most recently active stage."""
        row = _STAGE_TO_ROW.get(self._last_stage, "scan")
        return row.upper(), _TAG_COLORS[row]

    def on_stage(self, event: StageEvent) -> None:
        """Fold a stage lifecycle event into progress state and the feed."""
        self._last_stage = event.name
        self.stage_status[event.name] = event.status
        if event.status is StageStatus.PROGRESS and event.total > 0:
            self.stage_percent[event.name] = min(event.current / event.total * 100.0, 100.0)
        elif event.status in (StageStatus.DONE, StageStatus.WARN, StageStatus.SKIP):
            self.stage_percent[event.name] = 100.0
        elif event.status is StageStatus.START:
            self.stage_percent.setdefault(event.name, 0.0)
        if event.detail and event.status is not StageStatus.PROGRESS:
            self._append_detail(event.detail)

    def on_log(self, level: LogLevel, message: str) -> None:
        """Append a timestamped, stage-tagged status line to the live feed."""
        tag, color = self.current_tag()
        # no_wrap keeps one event on one row; long messages ellipsize instead
        # of wrapping and breaking the timestamp alignment.
        line = Text(no_wrap=True, overflow="ellipsis")
        line.append(f"[{datetime.now().strftime(_HMS)}] ", style=Style(color=theme.DASH_DIM))
        line.append(f"[{tag}] ", style=Style(color=color, bold=True))
        line.append(message, style=Style(color=_LOG_LEVEL_COLORS[level]))
        self.feed.append(line)

    def on_finding(self, finding: Finding) -> None:
        """Append a finding line with severity badge to the live feed."""
        color = _TAG_COLORS.get(finding.category.value, theme.DASH_DIM)
        line = Text(no_wrap=True, overflow="ellipsis")
        line.append(f"[{datetime.now().strftime(_HMS)}] ", style=Style(color=theme.DASH_DIM))
        line.append(f"[{finding.category.value.upper()}] ", style=Style(color=color, bold=True))
        line.append(f"{finding.title}  ", style=Style(color=theme.DASH_TEXT))
        line.append(
            f"[{finding.severity.value.upper()}] ",
            style=Style(color=theme.DASH_SEVERITY_COLORS[finding.severity], bold=True),
        )
        line.append(finding.url or finding.host, style=Style(color=theme.DASH_DIM))
        self.feed.append(line)

    def on_host(self, host: Host) -> None:
        """Append a discovered-host detail line (verbose mode only)."""
        self._append_detail(f"host: {host.url or host.host}")

    def crawl_requested(self) -> bool:
        """Whether the pipeline will run crawl for the selected categories."""
        return bool(self.ctx.categories & {Category.WEBVULN, Category.REDIRECT, Category.SECRETS})

    def display_rows(self) -> list[tuple[str, bool]]:
        """Return (row key, selected) pairs in display order.

        The crawl row only appears when crawl will run; every other row is
        always shown, dimmed when its category was not selected.
        """
        rows: list[tuple[str, bool]] = []
        for row in _ROW_ORDER:
            if row == "crawl":
                if self.crawl_requested():
                    rows.append((row, True))
                continue
            rows.append((row, Category(row) in self.ctx.categories))
        return rows

    def row_percent(self, row: str) -> float:
        """Return the aggregated percent for a display row.

        Members never seen count as 0 so a row with three sequential stages
        starts near zero and rises monotonically as each member finishes.
        """
        values: list[float] = []
        for name in _ROW_MEMBERS[row]:
            status = self.stage_status.get(name)
            if status in (StageStatus.DONE, StageStatus.WARN, StageStatus.SKIP):
                values.append(100.0)
            elif status is None:
                values.append(0.0)
            else:
                values.append(self.stage_percent.get(name, 0.0))
        return sum(values) / len(values)

    def row_state(self, row: str) -> str:
        """Return "done", "active", or "queued" for a display row."""
        members = _ROW_MEMBERS[row]
        percent = self.row_percent(row)
        if percent >= 100.0:
            return "done"
        active = any(self.stage_status.get(name) in (StageStatus.START, StageStatus.PROGRESS) for name in members)
        if percent > 0.0 or active:
            return "active"
        return "queued"

    def overall(self) -> float:
        """Return the mean percent across selected display rows."""
        selected = [row for row, ok in self.display_rows() if ok]
        if not selected:
            return 0.0
        return sum(self.row_percent(row) for row in selected) / len(selected)

    def _append_detail(self, detail: str) -> None:
        _, color = self.current_tag()
        line = Text(no_wrap=True, overflow="ellipsis")
        line.append(f"[{datetime.now().strftime(_HMS)}] ", style=Style(color=theme.DASH_DIM))
        line.append("  ↳ ", style=Style(color=color))
        line.append(detail, style=Style(color=theme.DASH_DIM))
        self.feed.append(line)


def build_dashboard(state: DashboardState) -> Layout:
    """Assemble the full three-column dashboard layout for one render pass."""
    header = Layout(name="header", size=9)
    body = Layout(name="body")
    footer = Layout(name="footer", size=1)
    root = Layout(name="root")
    root.split_column(header, body, footer)

    left = Layout(name="left", ratio=4)
    center = Layout(name="center", ratio=6)
    right = Layout(name="right", ratio=4)
    body.split_row(left, center, right)

    progress = Layout(name="progress")
    stats_panel = Layout(name="stats", size=9)
    left.split_column(progress, stats_panel)

    feed = Layout(name="feed")
    status = Layout(name="status", size=4)
    center.split_column(feed, status)

    summary = Layout(name="summary", size=13)
    recent = Layout(name="recent")
    report = Layout(name="report", size=3 if state.formats and state.report_dir else 0)
    right.split_column(summary, recent, report)

    header.update(_build_header(state))
    progress.update(_build_progress(state))
    stats_panel.update(LiveRebuild(lambda: _build_stats(state)))
    feed.update(_build_feed(state))
    status.update(_build_status(state))
    summary.update(_build_summary(state))
    recent.update(_build_recent(state))
    report.update(_build_report(state) if state.formats and state.report_dir else Text())
    footer.update(LiveRebuild(lambda: _build_footer(state)))
    return root


def _panel(renderable: RenderableType, title: str) -> Panel:
    """Wrap a renderable in the dashboard's standard dark panel chrome."""
    # Title styling rides on markup because older rich releases reject the
    # title_style kwarg on Panel.
    return Panel(
        renderable,
        title=f"[bold {theme.DASH_TITLE}]{title}[/]",
        title_align="left",
        border_style=theme.DASH_BORDER,
        style=Style(bgcolor=theme.DASH_BG_PANEL),
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _kv_grid(rows: list[tuple[str, str]], *, label_width: int) -> Table:
    """Build a borderless two-column label/value grid for the header boxes."""
    grid = Table.grid(expand=True)
    grid.add_column(style=theme.DASH_DIM, no_wrap=True, width=label_width)
    grid.add_column(style=theme.DASH_TEXT, overflow="ellipsis")
    for label, value in rows:
        grid.add_row(f"{label} :", value)
    return grid


def _build_header(state: DashboardState) -> RenderableType:
    ctx = state.ctx
    # box.SIMPLE instead of None: this rich version calls box.substitute
    # unguarded in Panel.__rich_console__, so box=None crashes on render.
    brand = Panel(
        Group(
            banner_text(),
            Text("DEEP WEB VULNERABILITY SCANNER CLI", style=Style(color=theme.DASH_DIM, bold=True)),
            Text("Recon → Scan → Discover → Report", style=Style(color=theme.DASH_ACCENT)),
        ),
        box=box.SIMPLE,
        style=Style(bgcolor=theme.DASH_BG_PANEL),
        padding=(0, 1),
    )
    config = _panel(
        _kv_grid(
            [
                ("Target", ctx.target_url),
                ("Scope", state.scope_file or "Not specified"),
                ("Categories", _categories_label(ctx.categories)),
                ("Rate Limit", f"{ctx.rate_limit} req/s"),
                ("Mode", ctx.mode),
                ("Output", _formats_label(state.formats)),
            ],
            label_width=_CONFIG_LABEL_WIDTH,
        ),
        title="SCAN CONFIG",
    )
    engine = _panel(_engine_lines(ctx), title="ENGINE")
    row = Layout(name="header_row")
    row.split_row(Layout(brand, size=56), Layout(config, ratio=1), Layout(engine, ratio=1))
    return row


def _engine_lines(ctx: ScanContext) -> RenderableType:
    builtin = Text()
    builtin.append("  Built-in engine  ", style=Style(color=theme.DASH_DIM))
    builtin.append("✓", style=Style(color=theme.DASH_OK, bold=True))
    found = sum(1 for ok in ctx.available_tools.values() if ok)
    total = len(ctx.available_tools)
    external = Text()
    external.append("  External tools  ", style=Style(color=theme.DASH_DIM))
    if total:
        external.append("✓", style=Style(color=theme.DASH_OK, bold=True))
        external.append(f" ({found}/{total}, optional)", style=Style(color=theme.DASH_DIM))
    else:
        external.append("- (optional)", style=Style(color=theme.DASH_DIM))
    quote1 = Text("  “More coverage.", style=Style(color=theme.DASH_DIM, italic=True))
    quote2 = Text("  Less blind spots.”", style=Style(color=theme.DASH_DIM, italic=True))
    return Group(builtin, external, Text(""), quote1, quote2)


def _build_progress(state: DashboardState) -> RenderableType:
    grid = Table.grid(expand=True)
    grid.add_column(no_wrap=True, width=12)
    grid.add_column(ratio=1, no_wrap=True)
    grid.add_column(justify="right", no_wrap=True, width=5)
    overall = 100.0 if state.finished else state.overall()
    grid.add_row(
        Text("Overall", style=Style(color=theme.DASH_TEXT, bold=True)),
        _bar(overall, done=overall >= 100.0),
        Text(f"{overall:.0f}%", style=Style(color=theme.DASH_ACCENT_BRIGHT)),
    )
    for row_key, selected in state.display_rows():
        if not selected:
            grid.add_row(
                Text(row_key, style=Style(color=theme.DASH_DIM)),
                Text("█" * _BAR_WIDTH, style=Style(color=theme.DASH_BAR_TRACK)),
                Text("—", style=Style(color=theme.DASH_DIM)),
            )
            continue
        percent = state.row_percent(row_key)
        row_state = state.row_state(row_key)
        name = Text()
        name.append("● ", style=Style(color=_DOT_COLORS[row_state], bold=True))
        name.append(row_key, style=Style(color=theme.DASH_TEXT))
        pct_color = theme.DASH_ACCENT_BRIGHT if row_state == "done" else theme.DASH_DIM
        grid.add_row(
            name, _bar(percent, done=row_state == "done"), Text(f"{percent:.0f}%", style=Style(color=pct_color))
        )
    return _panel(grid, title="SCAN PROGRESS")


def _build_stats(state: DashboardState) -> RenderableType:
    ctx = state.ctx
    rows = [
        ("Hosts discovered", str(len(ctx.hosts))),
        ("URLs queued", str(len(ctx.crawled_urls))),
        ("Requests sent", str(stats.request_count())),
        ("Response time", f"{stats.average_ms():.0f} ms"),
        ("Threads", str(ctx.config.ffuf_threads)),
    ]
    return _panel(_kv_grid(rows, label_width=_STATS_LABEL_WIDTH), title="LIVE STATS")


def _build_feed(state: DashboardState) -> RenderableType:
    content: RenderableType
    if state.feed:
        content = Group(*state.feed)
    else:
        content = Text("  waiting for scan events…", style=Style(color=theme.DASH_DIM))
    return _panel(content, title="LIVE SCAN")


def _build_status(state: DashboardState) -> RenderableType:
    overall = 100.0 if state.finished else state.overall()
    grid = Table.grid(expand=True)
    grid.add_column(ratio=1, no_wrap=True)
    grid.add_column(justify="right", no_wrap=True, width=5)
    grid.add_row(
        _bar(overall, done=state.finished or overall >= 100.0),
        Text(f"{overall:.0f}%", style=Style(color=theme.DASH_ACCENT_BRIGHT)),
    )
    count = len(state.ctx.categories)
    if state.finished:
        status = f"Complete.  ({count}/{len(ALL_CATEGORIES)} categories)"
        status_style = Style(color=theme.DASH_OK)
    else:
        status = f"Scanning...  ({count}/{len(ALL_CATEGORIES)} categories)"
        status_style = Style(color=theme.DASH_DIM)
    grid.add_row(Text(status, style=status_style), Text(""))
    return _panel(grid, title="OVERALL")


def _build_summary(state: DashboardState) -> RenderableType:
    counts = _severity_counts(state.ctx.findings)
    total = len(state.ctx.findings)
    head = Table.grid(expand=True)
    head.add_column(no_wrap=True)
    head.add_column(justify="right", no_wrap=True)
    head.add_row(
        Text("Total Findings", style=Style(color=theme.DASH_TEXT, bold=True)),
        Text(str(total), style=Style(color=theme.DASH_ACCENT_BRIGHT, bold=True)),
    )
    severity_rows: list[Text] = []
    for severity in _ROW_SEVERITIES:
        row = Text()
        row.append("● ", style=Style(color=theme.DASH_SEVERITY_COLORS[severity], bold=True))
        row.append(f"{severity.value.capitalize():<9}", style=Style(color=theme.DASH_TEXT))
        row.append(str(counts[severity]), style=Style(color=theme.DASH_TEXT, bold=True))
        severity_rows.append(row)
    left = Group(head, Text(""), *severity_rows)
    body = Table.grid(expand=True)
    body.add_column(ratio=1)
    body.add_column(no_wrap=True)
    body.add_row(left, Align.center(_donut_text(counts, total)))
    return _panel(body, title="FINDINGS SUMMARY")


def _build_recent(state: DashboardState) -> RenderableType:
    rows: list[RenderableType] = []
    hint = Table.grid(expand=True)
    hint.add_column(no_wrap=True)
    hint.add_column(justify="right", no_wrap=True)
    hint.add_row(Text(""), Text("View all →", style=Style(color=theme.DASH_DIM)))
    rows.append(hint)
    newest = list(reversed(state.ctx.findings[-_RECENT_MAX:]))
    if not newest:
        rows.append(Text("  No findings yet.", style=Style(color=theme.DASH_DIM)))
    for finding in newest:
        line = Table.grid(expand=True)
        line.add_column(no_wrap=True, overflow="ellipsis")
        line.add_column(justify="right", no_wrap=True, width=6)
        badge = Text()
        # Pad to 8 then a literal space: "CRITICAL" already fills 8 chars and
        # would otherwise run into the title with no separator.
        badge.append(
            f"{finding.severity.value.upper():<8} ",
            style=Style(color=theme.DASH_SEVERITY_COLORS[finding.severity], bold=True),
        )
        badge.append(finding.title, style=Style(color=theme.DASH_TEXT))
        line.add_row(badge, Text(_short_time(finding.timestamp), style=Style(color=theme.DASH_DIM)))
        rows.append(line)
        rows.append(
            Text(
                f"  {finding.url or finding.host}", style=Style(color=theme.DASH_DIM), no_wrap=True, overflow="ellipsis"
            )
        )
    return _panel(Group(*rows), title="RECENT FINDINGS")


def _build_report(state: DashboardState) -> RenderableType:
    line = Text()
    line.append("→  Report will be saved to ", style=Style(color=theme.DASH_DIM))
    line.append(state.report_dir or "", style=Style(color=theme.DASH_ACCENT_BRIGHT))
    return _panel(line, title="REPORT")


def _build_footer(state: DashboardState) -> RenderableType:
    left = Text(" ")
    left.append(f"Shaidra v{__version__}", style=Style(color=theme.DASH_ACCENT, bold=True))
    left.append("  |  ", style=Style(color=theme.DASH_DIM))
    left.append("Authorized testing only.", style=Style(color=theme.DASH_DIM))
    left.append("  |  ", style=Style(color=theme.DASH_DIM))
    left.append("https://github.com/santstyle/Shaidra", style=Style(color=theme.DASH_ACCENT))
    elapsed = time.monotonic() - state.ctx.start_time if state.ctx.start_time else 0.0
    right = Text(f"elapsed {_fmt_elapsed(elapsed)} ", style=Style(color=theme.DASH_DIM))
    grid = Table.grid(expand=True)
    # Column styles paint the dark strip across the full width; a size=1
    # footer slot cannot hold a boxed panel (content + rule = 2 lines).
    grid.add_column(style=Style(bgcolor=theme.DASH_BG_PANEL), no_wrap=True)
    grid.add_column(justify="right", no_wrap=True, style=Style(bgcolor=theme.DASH_BG_PANEL))
    grid.add_row(left, right)
    return grid


def _bar(percent: float, *, done: bool = False) -> Text:
    """Build a fixed-width block bar; done bars use the brighter accent."""
    filled = max(0, min(_BAR_WIDTH, round(percent / 100.0 * _BAR_WIDTH)))
    bar = Text()
    bar.append("█" * filled, style=Style(color=theme.DASH_ACCENT_BRIGHT if done else theme.DASH_ACCENT))
    bar.append("█" * (_BAR_WIDTH - filled), style=Style(color=theme.DASH_BAR_TRACK))
    return bar


def _donut_text(counts: dict[Severity, int], total: int) -> Text:
    """Draw the severity donut as a colored cell grid with a center total."""
    half_w = (_DONUT_W - 1) / 2.0
    half_h = (_DONUT_H - 1) / 2.0
    bounds = _slice_bounds(counts, total)
    labels = {
        int(half_h): (str(total), Style(color=theme.DASH_TEXT, bold=True)),
        int(half_h) + 1: ("findings", Style(color=theme.DASH_DIM)),
    }
    text = Text(no_wrap=True)
    for y in range(_DONUT_H):
        cells: list[tuple[str, Style | None]] = []
        for x in range(_DONUT_W):
            nx = (x - half_w) / half_w
            ny = (y - half_h) / half_h
            distance = math.hypot(nx, ny)
            if _DONUT_INNER <= distance <= _DONUT_OUTER:
                # atan2(nx, -ny) yields 0 at top, increasing clockwise.
                angle = (math.atan2(nx, -ny) / (2 * math.pi)) % 1.0
                cells.append(("█", Style(color=_slice_color(angle, bounds))))
            else:
                cells.append((" ", None))
        if y in labels:
            label, label_style = labels[y]
            start = (_DONUT_W - len(label)) // 2
            for i, ch in enumerate(label):
                cells[start + i] = (ch, label_style)
        for ch, cell_style in cells:
            text.append(ch, style=cell_style)
        if y != _DONUT_H - 1:
            text.append("\n")
    return text


def _slice_bounds(counts: dict[Severity, int], total: int) -> list[tuple[str, float]]:
    """Return (color, cumulative fraction) pairs for the donut slices."""
    if total <= 0:
        return []
    bounds: list[tuple[str, float]] = []
    accumulated = 0.0
    for severity in _SEVERITY_SLICE_ORDER:
        count = counts.get(severity, 0)
        if count <= 0:
            continue
        accumulated += count / total
        bounds.append((theme.DASH_SEVERITY_COLORS[severity], accumulated))
    return bounds


def _slice_color(angle: float, bounds: list[tuple[str, float]]) -> str:
    """Map a clockwise angle in [0, 1) to its severity color (or the track)."""
    for color, end in bounds:
        if angle < end:
            return color
    return theme.DASH_BAR_TRACK


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts = dict.fromkeys(Severity, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def _categories_label(selected: set[Category]) -> str:
    total = len(ALL_CATEGORIES)
    if len(selected) >= total:
        return f"All ({total})"
    return f"{len(selected)} of {total}"


def _formats_label(formats: frozenset[str]) -> str:
    if not formats:
        return "Not set (-o to save)"
    return " + ".join(_FORMAT_LABELS[name] for name in _FORMAT_ORDER if name in formats)


def _short_time(iso_timestamp: str) -> str:
    """Format an ISO-8601 timestamp as HH:MM for the recent-findings list."""
    try:
        return datetime.fromisoformat(iso_timestamp).strftime("%H:%M")
    except ValueError:
        return "--:--"


def _fmt_elapsed(seconds: float) -> str:
    total = int(seconds)
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes}:{secs:02d}"
