"""Tests for takeover and CVE-match shared helpers and parse paths."""

from __future__ import annotations

import asyncio
import json

from shaidra.core.config import Config
from shaidra.core.events import EventBus
from shaidra.core.models import Category, Host, ScanContext, Severity, StageStatus
from shaidra.core.scope import Scope
from shaidra.stages import cve_match, takeover
from shaidra.stages.takeover import _NucleiTakeover


def _ctx(*, tools: dict[str, bool] | None = None) -> ScanContext:
    ctx = ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.TAKEOVER},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=False,
    )
    if tools is not None:
        ctx.available_tools.update(tools)
    ctx.add_host(Host(host="example.com", url="https://example.com", is_live=True))
    ctx.add_host(Host(host="evil.com", url="https://evil.com", is_live=True))
    return ctx


def test_live_target_urls_filters_out_of_scope() -> None:
    assert takeover._live_target_urls(_ctx()) == ["https://example.com"]


def test_live_target_urls_dedup() -> None:
    ctx = ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.CVE},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=False,
    )
    ctx.add_host(Host(host="example.com", url="https://example.com", is_live=True))
    ctx.add_host(Host(host="www.example.com", url="https://example.com", is_live=True))
    assert cve_match._live_target_urls(ctx) == ["https://example.com"]


def test_live_target_urls_https_fallback() -> None:
    ctx = ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.CVE},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=False,
    )
    ctx.add_host(Host(host="example.com", is_live=True))
    assert cve_match._live_target_urls(ctx) == ["https://example.com"]


def test_subjack_verdicts() -> None:
    assert "Vulnerable" in takeover._SUBJACK_VERDICTS
    assert "Hijackable" in takeover._SUBJACK_VERDICTS
    assert "Not Vulnerable" not in takeover._SUBJACK_VERDICTS


def test_map_severity() -> None:
    assert takeover._map_severity("high") is Severity.HIGH
    assert takeover._map_severity("critical") is Severity.CRITICAL
    assert takeover._map_severity("info") is Severity.INFO
    assert takeover._map_severity("weird") is Severity.INFO
    assert takeover._map_severity(None) is Severity.INFO


def test_parse_nuclei_line_valid() -> None:
    payload = {
        "template-id": "takeover/takeover",
        "info": {"name": "GitHub Pages", "severity": "medium"},
        "host": "blog.example.com",
        "matched-at": "blog.example.com",
    }
    hit = takeover._parse_nuclei_line(json.dumps(payload))
    assert hit is not None
    assert hit.template_id == "takeover/takeover"
    assert hit.severity is Severity.MEDIUM
    assert hit.host == "blog.example.com"


def test_parse_nuclei_line_missing_host_returns_none() -> None:
    payload = {"template-id": "t", "info": {"name": "x"}}
    assert takeover._parse_nuclei_line(json.dumps(payload)) is None
    assert takeover._parse_nuclei_line("not-json") is None


def test_nuclei_finding_shape() -> None:
    hit = _NucleiTakeover(
        template_id="t1",
        name="GitHub Pages",
        severity=Severity.MEDIUM,
        host="blog.example.com",
        matched_at="https://blog.example.com",
        raw={"a": 1},
    )
    finding = takeover._nuclei_finding(hit)
    assert finding.category is Category.TAKEOVER
    assert finding.severity is Severity.MEDIUM
    assert "GitHub Pages" in finding.title


def test_cve_parse_nuclei_line_extracts_cve() -> None:
    payload = {
        "template-id": "cves/2021/CVE-2021-1234",
        "info": {
            "name": "Apache RCE",
            "severity": "critical",
            "classification": {"cve-id": ["CVE-2021-1234"]},
        },
        "host": "example.com",
        "matched-at": "https://example.com",
    }
    hit = cve_match._parse_nuclei_line(json.dumps(payload))
    assert hit is not None
    assert hit.cve == "CVE-2021-1234"
    assert hit.severity is Severity.CRITICAL


def test_takeover_run_skips_without_tools() -> None:
    ctx = _ctx(tools={"nuclei": False, "subjack": False})
    ctx.available_tools.clear()

    async def scenario() -> list[object]:
        bus = EventBus()
        await takeover.run(ctx, bus)
        await bus.close()
        events: list[object] = []
        while True:
            event = await bus.next_event()
            if event is None:
                return events
            events.append(event)

    events = asyncio.run(scenario())
    statuses = [getattr(e, "status", None) for e in events]
    assert StageStatus.SKIP in statuses
