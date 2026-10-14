"""Tests for the dark-purple dashboard live view (rendered via a recording console)."""

from __future__ import annotations

from rich.console import Console

from shaidra.core.config import Config
from shaidra.core.events import FindingEvent, StageEvent
from shaidra.core.models import ALL_CATEGORIES, Category, Finding, LogLevel, ScanContext, Severity, StageStatus
from shaidra.core.scope import Scope
from shaidra.output.dashboard import (
    MIN_DASHBOARD_HEIGHT,
    MIN_DASHBOARD_WIDTH,
    DashboardState,
    build_dashboard,
)
from shaidra.output.terminal import TerminalRenderer
from shaidra.utils import stats


def _ctx() -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories=set(ALL_CATEGORIES),
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
    )


def _finding(title: str, severity: Severity, category: Category = Category.WEBVULN) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        host="example.com",
        tool="builtin",
        url="https://example.com/?q=test",
    )


def _dashboard_console() -> Console:
    return Console(record=True, width=160, height=45, force_terminal=True, color_system="truecolor")


def _populated_state(ctx: ScanContext | None = None) -> DashboardState:
    ctx = ctx or _ctx()
    state = DashboardState(
        ctx=ctx,
        scope_file="scope.txt",
        formats=frozenset({"json", "markdown", "txt"}),
        report_dir="./reports",
    )
    state.on_stage(StageEvent(name="recon", status=StageStatus.START))
    state.on_stage(StageEvent(name="recon", status=StageStatus.PROGRESS, current=5, total=10))
    state.on_stage(StageEvent(name="recon", status=StageStatus.DONE, detail="42 subdomains"))
    state.on_log(LogLevel.INFO, "Enumerating subdomains (crt.sh + hackertarget)...")
    state.on_stage(StageEvent(name="Web vulns", status=StageStatus.START))
    for finding in (
        _finding("XSS (reflected)", Severity.HIGH),
        _finding("SQL injection", Severity.CRITICAL),
        _finding("Directory listing", Severity.LOW),
    ):
        # Mirror TerminalRenderer._on_finding: findings land on the context
        # first, so the summary and recent panels have data to render.
        ctx.findings.append(finding)
        state.on_finding(finding)
    return state


def test_dashboard_renders_core_panels_and_content() -> None:
    console = _dashboard_console()
    state = _populated_state()
    console.print(build_dashboard(state))
    text = console.export_text()
    for needle in (
        "SCAN PROGRESS",
        "LIVE STATS",
        "LIVE SCAN",
        "FINDINGS SUMMARY",
        "RECENT FINDINGS",
        "https://example.com",
        "Rate Limit",
        "Authorized testing only",
        "Enumerating subdomains",
        "XSS (reflected)",
        "42 subdomains",
    ):
        assert needle in text, f"missing {needle!r}"


def test_dashboard_shows_severity_rows_and_total() -> None:
    console = _dashboard_console()
    state = _populated_state()
    console.print(build_dashboard(state))
    text = console.export_text()
    assert "Total Findings" in text
    for name in ("Critical", "High", "Medium", "Low"):
        assert name in text


def test_narrow_console_selects_fallback() -> None:
    narrow = Console(record=True, width=MIN_DASHBOARD_WIDTH - 1, height=40, force_terminal=True)
    assert TerminalRenderer(narrow)._dashboard_enabled is False
    short = Console(record=True, width=160, height=MIN_DASHBOARD_HEIGHT - 1, force_terminal=True)
    assert TerminalRenderer(short)._dashboard_enabled is False
    wide = _dashboard_console()
    assert TerminalRenderer(wide)._dashboard_enabled is True


def test_renderer_appends_findings_even_when_dashboard_active() -> None:
    ctx = _ctx()
    console = _dashboard_console()
    renderer = TerminalRenderer(console)
    renderer._state = _populated_state(ctx)  # force the dashboard code path
    renderer._handle(FindingEvent(finding=_finding("Open Redirect", Severity.MEDIUM)), ctx)
    assert any(f.title == "Open Redirect" for f in ctx.findings)


def test_stats_counters_reset() -> None:
    stats.reset()
    stats.record_request(10.0)
    stats.record_request(20.0)
    assert stats.request_count() == 2
    assert stats.average_ms() == 15.0
    stats.reset()
    assert stats.request_count() == 0
    assert stats.average_ms() == 0.0


def test_stage_rows_reach_100_on_real_stage_names() -> None:
    """Every bus stage name the pipeline actually emits must fill its row.

    A name drift between stages/*.py and _ROW_MEMBERS silently freezes that
    row at 0% and drags the overall bar down (seen live at 54%).
    """
    ctx = _ctx()
    state = DashboardState(ctx=ctx)
    for name in (
        "recon",
        "fingerprint",
        "port-scan",
        "Crawl",
        "Content discovery",
        "API scan",
        "CMS scan",
        "Web vulns",
        "open_redirect",
        "Takeover detection",
        "CVE matching",
        "Secret scan",
        "cors",
        "JWT",
        "Misconfiguration",
    ):
        state.on_stage(StageEvent(name=name, status=StageStatus.START))
        state.on_stage(StageEvent(name=name, status=StageStatus.DONE, detail="ok"))
    assert state.overall() == 100.0
    for row, _selected in state.display_rows():
        assert state.row_percent(row) == 100.0, f"row {row} not full"


def test_finished_forces_overall_complete() -> None:
    ctx = _ctx()
    state = DashboardState(ctx=ctx)
    state.on_stage(StageEvent(name="recon", status=StageStatus.DONE))
    state.finished = True
    console = _dashboard_console()
    console.print(build_dashboard(state))
    text = console.export_text()
    assert "Complete." in text
    assert "Scanning..." not in text
