"""Tests for the full-screen Textual TUI: launch gating, logo sampling, and app wiring."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest
from textual.widgets import DataTable, Footer, RichLog, Static

from shaidra.core.config import Config
from shaidra.core.events import FindingEvent, StageEvent
from shaidra.core.models import ALL_CATEGORIES, Category, Finding, ScanContext, Severity, StageStatus
from shaidra.core.scope import Scope
from shaidra.output.banner import logo_art_text_sampled
from shaidra.output.logo_art import LOGO_HEIGHT, LOGO_WIDTH
from shaidra.tui import should_launch_tui
from shaidra.tui.app import ScanCompleteMsg, ShaidraApp, SummaryScreen


class _FakeStream:
    def __init__(self, is_tty: bool) -> None:
        self._is_tty = is_tty

    def isatty(self) -> bool:
        return self._is_tty


class _NoScanApp(ShaidraApp):
    def _run_scan(self) -> None:
        return None


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


def _finding(title: str, severity: Severity, *, url: str = "https://example.com/?q=test") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=Category.WEBVULN,
        host="example.com",
        tool="builtin",
        url=url,
    )


def _app() -> _NoScanApp:
    return _NoScanApp(_ctx(), formats=frozenset(), outdir=Path("reports"), base_name="test")


def test_quiet_short_circuits_before_tty_check(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", _FakeStream(True))
    assert should_launch_tui(quiet=True) is False


def test_non_tty_stdout_disables_tui(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", _FakeStream(False))
    assert should_launch_tui(quiet=False) is False


def test_dumb_terminal_disables_tui(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", _FakeStream(True))
    monkeypatch.setenv("TERM", "dumb")
    assert should_launch_tui(quiet=False) is False


def test_interactive_terminal_enables_tui(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "stdout", _FakeStream(True))
    monkeypatch.delenv("TERM", raising=False)
    assert should_launch_tui(quiet=False) is True


def test_sampled_logo_keeps_width_and_cuts_height() -> None:
    sampled = logo_art_text_sampled(5).plain.splitlines()
    assert len(sampled) == 5
    assert all(len(line) == LOGO_WIDTH for line in sampled)
    full = logo_art_text_sampled(LOGO_HEIGHT).plain.splitlines()
    assert len(full) == LOGO_HEIGHT
    assert all(len(line) == LOGO_WIDTH for line in full)


def test_app_composes_dashboard_panels() -> None:
    async def scenario() -> None:
        app = _app()
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            assert app.query_one("#logo", Static)
            assert app.query_one("#header-info", Static)
            assert app.query_one("#progress", Static)
            assert app.query_one("#feed", RichLog)
            assert app.query_one("#findings", DataTable)
            assert app.query_one(Footer)

    asyncio.run(scenario())


def test_finding_event_lands_in_table_and_ctx() -> None:
    finding = _finding("SQL injection", Severity.CRITICAL)

    async def scenario() -> None:
        app = _app()
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            app._dispatch(FindingEvent(finding=finding))
            await pilot.pause()
            table = app.query_one("#findings", DataTable)
            assert table.row_count == 1
            assert table.get_row_at(0)[2] == finding.url
            assert app.ctx.findings == [finding]

    asyncio.run(scenario())


def test_stage_event_updates_progress_state() -> None:
    async def scenario() -> None:
        app = _app()
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            app._dispatch(StageEvent(name="recon", status=StageStatus.START))
            app._dispatch(StageEvent(name="recon", status=StageStatus.PROGRESS, current=5, total=10))
            await pilot.pause()
            assert app.state.stage_percent["recon"] == 50.0

    asyncio.run(scenario())


def test_scan_complete_opens_summary_and_escape_closes() -> None:
    finding = _finding("Reflected XSS", Severity.HIGH)

    async def scenario() -> None:
        app = _app()
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            app._dispatch(FindingEvent(finding=finding))
            app.post_message(ScanCompleteMsg(duration=1.5, report_paths={"JSON": "reports/test.json"}))
            await pilot.pause()
            screen = app.screen
            assert isinstance(screen, SummaryScreen)
            table = screen.query_one("#summary-table", DataTable)
            assert table.row_count == 1
            assert table.get_row_at(0)[2] == finding.url
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, SummaryScreen)

    asyncio.run(scenario())


def test_summary_binding_pushes_and_dismisses_screen() -> None:
    async def scenario() -> None:
        app = _app()
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause()
            await pilot.press("s")
            await pilot.pause()
            assert isinstance(app.screen, SummaryScreen)
            await pilot.press("escape")
            await pilot.pause()
            assert not isinstance(app.screen, SummaryScreen)

    asyncio.run(scenario())
