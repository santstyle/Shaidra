"""Tests for shared domain models: host merging, serialization, and the
event-bus emitters not exercised by existing dashboard/TUI tests."""

from __future__ import annotations

import asyncio
from typing import Any

from shaidra.core.config import Config
from shaidra.core.events import EventBus, FindingEvent, HostEvent, StageEvent
from shaidra.core.models import Category, Finding, FormTarget, Host, ScanContext, Severity, StageStatus
from shaidra.core.scope import Scope


def _ctx() -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.RECON},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
    )


async def _collect(bus: EventBus) -> list[Any]:
    await bus.close()
    events: list[Any] = []
    while True:
        event = await bus.next_event()
        if event is None:
            return events
        events.append(event)


class TestHostMerging:
    def test_first_host_is_inserted_as_is(self) -> None:
        ctx = _ctx()
        host = Host(host="a.example.com", ip="192.0.2.1")
        assert ctx.add_host(host) is host
        assert ctx.hosts == {"a.example.com": host}

    def test_later_stage_enriches_empty_fields_without_clobbering(self) -> None:
        ctx = _ctx()
        ctx.add_host(Host(host="a.example.com", ip="192.0.2.1", is_live=True))
        merged = ctx.add_host(
            Host(
                host="a.example.com",
                url="https://a.example.com",
                title="Home",
                server="nginx",
                status_code=200,
                ip="192.0.2.999",
            )
        )
        assert merged.ip == "192.0.2.1"
        assert merged.url == "https://a.example.com"
        assert merged.title == "Home"
        assert merged.server == "nginx"
        assert merged.status_code == 200
        assert merged.is_live is True

    def test_tech_list_unions_without_duplicates(self) -> None:
        ctx = _ctx()
        ctx.add_host(Host(host="a.example.com", tech=["nginx"]))
        merged = ctx.add_host(Host(host="a.example.com", tech=["nginx", "php"]))
        assert merged.tech == ["nginx", "php"]

    def test_cdn_and_live_flags_are_monotonic(self) -> None:
        ctx = _ctx()
        ctx.add_host(Host(host="a.example.com", cdn=True, is_live=True))
        merged = ctx.add_host(Host(host="a.example.com", cdn=False, is_live=False))
        assert merged.cdn is True
        assert merged.is_live is True


class TestContextHelpers:
    def test_live_hosts_filters_dead_entries(self) -> None:
        ctx = _ctx()
        ctx.add_host(Host(host="live.example.com", is_live=True))
        ctx.add_host(Host(host="dead.example.com", is_live=False))
        assert [h.host for h in ctx.live_hosts()] == ["live.example.com"]

    def test_has_tool_reflects_available_tools(self) -> None:
        ctx = _ctx()
        assert ctx.has_tool("nuclei") is False
        ctx.available_tools["nuclei"] = True
        assert ctx.has_tool("nuclei") is True


class TestSerialization:
    def test_host_to_dict(self) -> None:
        host = Host(host="a.example.com", url="https://a.example.com", is_live=True, tech=["nginx"])
        payload = host.to_dict()
        assert payload["host"] == "a.example.com"
        assert payload["is_live"] is True
        assert payload["tech"] == ["nginx"]

    def test_form_target_to_dict(self) -> None:
        form = FormTarget(
            page_url="https://example.com/form",
            action_url="https://example.com/submit",
            method="POST",
            fields={"user": "", "pass": ""},
            has_csrf_token=True,
        )
        assert form.to_dict() == {
            "page_url": "https://example.com/form",
            "action_url": "https://example.com/submit",
            "method": "POST",
            "fields": {"user": "", "pass": ""},
            "has_csrf_token": True,
        }

    def test_finding_to_dict_serializes_enums_and_shallow_copies_raw(self) -> None:
        raw: dict[str, Any] = {"nested": {"a": 1}, "top": 2}
        finding = Finding(
            title="T",
            severity=Severity.HIGH,
            category=Category.CMS,
            host="example.com",
            tool="test",
            raw=raw,
        )
        payload = finding.to_dict()
        assert payload["severity"] == "high"
        assert payload["category"] == "cms"
        assert payload["raw"] == {"nested": {"a": 1}, "top": 2}
        payload["raw"]["top"] = 99  # shallow copy: top level detached
        assert raw["top"] == 2


class TestEventBusEmitters:
    def test_host_event(self) -> None:
        async def _scenario() -> list[Any]:
            bus = EventBus()
            host = Host(host="a.example.com")
            await bus.host(host)
            return await _collect(bus)

        events = asyncio.run(_scenario())
        assert isinstance(events[0], HostEvent) and events[0].host.host == "a.example.com"

    def test_stage_progress_event(self) -> None:
        async def _scenario() -> StageEvent:
            bus = EventBus()
            await bus.stage_progress("Crawl", 3, 10)
            await bus.close()
            event = await bus.next_event()
            assert isinstance(event, StageEvent)
            return event

        event = asyncio.run(_scenario())
        assert event.status is StageStatus.PROGRESS
        assert (event.current, event.total, event.name) == (3, 10, "Crawl")

    def test_stage_skip_event(self) -> None:
        async def _scenario() -> StageEvent:
            bus = EventBus()
            await bus.stage_skip("CMS scan", "no tools")
            await bus.close()
            event = await bus.next_event()
            assert isinstance(event, StageEvent)
            return event

        event = asyncio.run(_scenario())
        assert event.status is StageStatus.SKIP and event.detail == "no tools"

    def test_stage_warn_event(self) -> None:
        async def _scenario() -> StageEvent:
            bus = EventBus()
            await bus.stage_warn("Recon", "partial")
            await bus.close()
            event = await bus.next_event()
            assert isinstance(event, StageEvent)
            return event

        event = asyncio.run(_scenario())
        assert event.status is StageStatus.WARN and event.detail == "partial"

    def test_finding_event(self) -> None:
        async def _scenario() -> FindingEvent:
            bus = EventBus()
            finding = Finding(
                title="T",
                severity=Severity.LOW,
                category=Category.CORS,
                host="example.com",
                tool="test",
            )
            await bus.finding(finding)
            await bus.close()
            event = await bus.next_event()
            assert isinstance(event, FindingEvent)
            return event

        event = asyncio.run(_scenario())
        assert event.finding.title == "T"
