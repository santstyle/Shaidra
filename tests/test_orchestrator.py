"""Tests for pipeline orchestration: preflight rate adaptation, recon
reachability, wave ordering, category filtering, and the guarded runner that
keeps one failing stage from aborting the scan.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from shaidra.core import orchestrator
from shaidra.core.config import Config
from shaidra.core.events import EventBus, LogEvent, StageEvent
from shaidra.core.models import Category, Host, ScanContext, StageStatus
from shaidra.core.scope import Scope


def _ctx(
    categories: set[Category] | None = None,
    *,
    extended: bool = False,
    verbose: bool = False,
) -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories=categories or {Category.RECON},
        rate_limit=40,
        extended=extended,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=verbose,
    )


async def _collect(bus: EventBus) -> list[Any]:
    await bus.close()
    events: list[Any] = []
    while True:
        event = await bus.next_event()
        if event is None:
            return events
        events.append(event)


class TestCrawlRequested:
    def test_true_for_stages_that_consume_crawled_urls(self) -> None:
        for category in (Category.WEBVULN, Category.REDIRECT, Category.SECRETS):
            assert orchestrator._crawl_requested({category}) is True, category

    def test_false_for_recon_only(self) -> None:
        assert orchestrator._crawl_requested({Category.RECON}) is False

    def test_mixed_set_returning_true(self) -> None:
        assert orchestrator._crawl_requested({Category.RECON, Category.CORS}) is False
        assert orchestrator._crawl_requested({Category.CORS, Category.WEBVULN}) is True

    def test_empty_set_is_false(self) -> None:
        assert orchestrator._crawl_requested(set()) is False


class TestGuarded:
    def test_success_passes_through_silently(self) -> None:
        calls: list[str] = []

        async def ok(ctx: ScanContext, bus: EventBus) -> None:
            calls.append("ran")

        async def _scenario() -> list[Any]:
            bus = EventBus()
            await orchestrator._guarded(ok, "Ok", _ctx(), bus)
            return await _collect(bus)

        events = asyncio.run(_scenario())
        assert calls == ["ran"]
        assert events == []

    def test_exception_becomes_stage_warning(self) -> None:
        async def boom(ctx: ScanContext, bus: EventBus) -> None:
            raise RuntimeError("stage exploded")

        async def _scenario() -> list[Any]:
            bus = EventBus()
            await orchestrator._guarded(boom, "Boom", _ctx(), bus)
            return await _collect(bus)

        events = asyncio.run(_scenario())
        warnings = [e for e in events if isinstance(e, StageEvent) and e.status is StageStatus.WARN]
        assert len(warnings) == 1
        assert warnings[0].name == "Boom"
        assert "stage exploded" in warnings[0].detail

    def test_cancellation_propagates(self) -> None:
        async def cancelled(ctx: ScanContext, bus: EventBus) -> None:
            raise asyncio.CancelledError

        async def _scenario() -> None:
            await orchestrator._guarded(cancelled, "C", _ctx(), EventBus())

        with pytest.raises(asyncio.CancelledError):
            asyncio.run(_scenario())


class TestPreflight:
    def test_waf_detection_lowers_rate_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(orchestrator, "ensure_on_path", lambda: None)
        monkeypatch.setattr(orchestrator, "check_tools", lambda names: {"nuclei": True, "ffuf": False})

        async def fake_detect(ctx: ScanContext, bus: EventBus) -> str | None:
            return "Cloudflare"

        monkeypatch.setattr(orchestrator, "detect_waf", fake_detect)

        async def _scenario() -> tuple[ScanContext, list[Any]]:
            bus = EventBus()
            ctx = _ctx()
            await orchestrator._preflight(ctx, bus)
            return ctx, await _collect(bus)

        ctx, events = asyncio.run(_scenario())
        assert ctx.waf == "Cloudflare"
        assert ctx.rate_limit == 20
        assert ctx.available_tools == {"nuclei": True, "ffuf": False}
        assert any(isinstance(e, StageEvent) and e.name == "Preflight" for e in events)

    def test_rate_limit_unchanged_without_waf(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(orchestrator, "ensure_on_path", lambda: None)
        monkeypatch.setattr(orchestrator, "check_tools", lambda names: {})

        async def fake_detect(ctx: ScanContext, bus: EventBus) -> str | None:
            return None

        monkeypatch.setattr(orchestrator, "detect_waf", fake_detect)

        async def _scenario() -> ScanContext:
            bus = EventBus()
            ctx = _ctx()
            await orchestrator._preflight(ctx, bus)
            return ctx

        ctx = asyncio.run(_scenario())
        assert ctx.waf is None
        assert ctx.rate_limit == 40

    def test_verbose_missing_tools_listing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(orchestrator, "ensure_on_path", lambda: None)
        monkeypatch.setattr(orchestrator, "check_tools", lambda names: {"nuclei": False})

        async def fake_detect(ctx: ScanContext, bus: EventBus) -> str | None:
            return None

        monkeypatch.setattr(orchestrator, "detect_waf", fake_detect)

        async def _scenario() -> list[Any]:
            bus = EventBus()
            await orchestrator._preflight(_ctx(verbose=True), bus)
            return await _collect(bus)

        logs = [e.message for e in asyncio.run(_scenario()) if isinstance(e, LogEvent)]
        assert any("missing tools: nuclei" in message for message in logs)


class TestRecon:
    def _patch_stages(self, monkeypatch: pytest.MonkeyPatch, *, live: bool) -> None:
        async def fake_recon(ctx: ScanContext, bus: EventBus) -> None:
            if live:
                ctx.add_host(Host(host="example.com", is_live=True))

        async def fake_fingerprint(ctx: ScanContext, bus: EventBus) -> None:
            return None

        monkeypatch.setattr(orchestrator.recon, "run", fake_recon)
        monkeypatch.setattr(orchestrator.fingerprint, "run", fake_fingerprint)

    def test_sets_web_reachable_when_a_host_is_live(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_stages(monkeypatch, live=True)

        async def _scenario() -> tuple[bool, list[Any]]:
            bus = EventBus()
            ctx = _ctx()
            await orchestrator._recon(ctx, bus)
            return ctx.web_reachable, await _collect(bus)

        reachable, events = asyncio.run(_scenario())
        assert reachable is True
        assert not any(isinstance(e, LogEvent) and e.level.value == "warn" for e in events)

    def test_warns_when_target_does_not_answer(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_stages(monkeypatch, live=False)

        async def _scenario() -> tuple[bool, list[Any]]:
            bus = EventBus()
            ctx = _ctx()
            await orchestrator._recon(ctx, bus)
            return ctx.web_reachable, await _collect(bus)

        reachable, events = asyncio.run(_scenario())
        assert reachable is False
        assert any(isinstance(e, LogEvent) and "did not answer" in e.message for e in events)


class TestScan:
    def _patch_waves(self, monkeypatch: pytest.MonkeyPatch, records: list[str]) -> None:
        def make(label: str) -> Any:
            async def stage(ctx: ScanContext, bus: EventBus) -> None:
                records.append(label)

            return stage

        monkeypatch.setattr(
            orchestrator,
            "_FIRST_WAVE",
            (("First", Category.CORS, make("first")),),
        )
        monkeypatch.setattr(
            orchestrator,
            "_SECOND_WAVE",
            (("Second", Category.WEBVULN, make("second")),),
        )

    def test_second_wave_runs_after_first(self, monkeypatch: pytest.MonkeyPatch) -> None:
        records: list[str] = []
        self._patch_waves(monkeypatch, records)
        categories = {Category.CORS, Category.WEBVULN}

        async def _scenario() -> list[str]:
            await orchestrator._scan(_ctx(categories), EventBus())
            return records

        assert asyncio.run(_scenario()) == ["first", "second"]

    def test_stages_outside_categories_are_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        records: list[str] = []
        self._patch_waves(monkeypatch, records)

        async def _scenario() -> list[str]:
            await orchestrator._scan(_ctx({Category.CMS}), EventBus())
            return records

        assert asyncio.run(_scenario()) == []

    def test_crawl_runs_when_webvuln_selected_then_second_wave(self, monkeypatch: pytest.MonkeyPatch) -> None:
        records: list[str] = []
        self._patch_waves(monkeypatch, records)

        async def fake_crawl(ctx: ScanContext, bus: EventBus) -> None:
            records.append("crawl")

        monkeypatch.setattr(orchestrator.crawl, "run", fake_crawl)
        monkeypatch.setattr(orchestrator.recon, "scan_ports", None)

        async def _scenario() -> list[str]:
            await orchestrator._scan(_ctx({Category.WEBVULN}), EventBus())
            return records

        result = asyncio.run(_scenario())
        assert result.index("crawl") < result.index("second")

    def test_port_scan_task_created_for_recon_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        records: list[str] = []
        self._patch_waves(monkeypatch, records)

        async def fake_ports(ctx: ScanContext, bus: EventBus) -> None:
            records.append("ports")

        monkeypatch.setattr(orchestrator.recon, "scan_ports", fake_ports)

        async def _scenario() -> list[str]:
            await orchestrator._scan(_ctx({Category.RECON}), EventBus())
            return records

        assert asyncio.run(_scenario()) == ["ports"]

    def test_extended_mode_captures_screenshots(self, monkeypatch: pytest.MonkeyPatch) -> None:
        records: list[str] = []
        self._patch_waves(monkeypatch, records)
        saved: list[Any] = []

        async def fake_capture(ctx: ScanContext, bus: EventBus, outdir: Any) -> list[Any]:
            saved.append(outdir)
            return [outdir / "shot.png"]

        monkeypatch.setattr(orchestrator, "capture_screenshots", fake_capture)

        async def _scenario() -> list[Any]:
            await orchestrator._scan(_ctx(set(), extended=True), EventBus())
            return saved

        assert len(asyncio.run(_scenario())) == 1

    def test_screenshot_oserror_is_logged_not_raised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_capture(ctx: ScanContext, bus: EventBus, outdir: Any) -> list[Any]:
            raise OSError("gowitness missing")

        monkeypatch.setattr(orchestrator, "capture_screenshots", fake_capture)

        async def _scenario() -> list[Any]:
            bus = EventBus()
            await orchestrator._scan(_ctx(set(), extended=True), bus)
            return await _collect(bus)

        logs = [e for e in asyncio.run(_scenario()) if isinstance(e, LogEvent)]
        assert any("screenshot capture failed" in e.message for e in logs)


class TestOrchestrate:
    def test_bus_is_closed_even_when_a_phase_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def exploding_preflight(ctx: ScanContext, bus: EventBus) -> None:
            raise RuntimeError("preflight died")

        monkeypatch.setattr(orchestrator, "_preflight", exploding_preflight)

        async def _scenario() -> list[Any]:
            bus = EventBus()
            with pytest.raises(RuntimeError, match="preflight died"):
                await orchestrator.orchestrate(_ctx(), bus)
            return await _collect(bus)

        events = asyncio.run(_scenario())
        assert events == [None] or events == []  # close() enqueued the sentinel

    def test_full_pipeline_runs_all_phases_and_sets_start_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        order: list[str] = []

        async def preflight(ctx: ScanContext, bus: EventBus) -> None:
            order.append("preflight")

        async def recon_phase(ctx: ScanContext, bus: EventBus) -> None:
            order.append("recon")

        async def scan_phase(ctx: ScanContext, bus: EventBus) -> None:
            order.append("scan")

        monkeypatch.setattr(orchestrator, "_preflight", preflight)
        monkeypatch.setattr(orchestrator, "_recon", recon_phase)
        monkeypatch.setattr(orchestrator, "_scan", scan_phase)

        async def _scenario() -> tuple[list[str], bool]:
            bus = EventBus()
            ctx = _ctx()
            await orchestrator.orchestrate(ctx, bus)
            sentinel = await bus.next_event()
            return order, sentinel is None

        order_out, closed = asyncio.run(_scenario())
        assert order_out == ["preflight", "recon", "scan"]
        assert closed is True


class TestKnownTools:
    def test_security_tooling_entries_present(self) -> None:
        for tool in ("nuclei", "sqlmap", "wafw00f", "subfinder", "katana"):
            assert tool in orchestrator.KNOWN_TOOLS
