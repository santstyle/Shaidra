"""Tests for WAF fingerprinting — both the wafw00f report parser and the
built-in header-signature fallback that tunes the rate limit when wafw00f
is absent.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, ClassVar, Self

import httpx
import pytest

from shaidra.core import waf_detect
from shaidra.core.config import Config
from shaidra.core.events import EventBus, LogEvent, StageEvent
from shaidra.core.models import Category, LogLevel, ScanContext, StageStatus
from shaidra.core.scope import Scope
from shaidra.utils.process import ToolResult


def _ctx(*, tools: dict[str, bool] | None = None) -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.RECON},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        available_tools=tools or {},
    )


class TestWafw00fJsonParsing:
    def test_json_object_with_detected_firewall(self) -> None:
        payload = '{"detected": true, "firewall": "Cloudflare"}'
        assert waf_detect._parse_wafw00f(payload) == "Cloudflare"

    def test_json_list_returns_first_detected_firewall(self) -> None:
        payload = '[{"detected": false, "firewall": "None"}, {"detected": true, "firewall": "AWS WAF"}]'
        assert waf_detect._parse_wafw00f(payload) == "AWS WAF"

    def test_not_detected_returns_none(self) -> None:
        assert waf_detect._parse_wafw00f('{"detected": false, "firewall": "Cloudflare"}') is None

    def test_firewall_none_string_returns_none(self) -> None:
        assert waf_detect._parse_wafw00f('{"detected": true, "firewall": "none"}') is None

    def test_non_dict_entries_ignored(self) -> None:
        assert waf_detect._parse_wafw00f('[42, "text", {"detected": true, "firewall": "Sucuri"}]') == "Sucuri"
        assert waf_detect._parse_wafw00f('"just a string"') is None
        assert waf_detect._parse_wafw00f("[1, 2, 3]") is None


class TestWafw00fTextParsing:
    def test_extracts_firewall_name_from_behind_line(self) -> None:
        stdout = "example.com is behind Cloudflare CDN\nother line\n"
        assert waf_detect._parse_wafw00f(stdout) == "Cloudflare CDN"

    def test_marker_matching_is_case_insensitive(self) -> None:
        # Regression: the old implementation matched case-insensitively but
        # split case-sensitively, raising IndexError on uppercase markers.
        assert waf_detect._parse_wafw00f("example.com IS BEHIND AWS WAF") == "AWS WAF"
        assert waf_detect._parse_wafw00f("example.com is behind Cloudflare") == "Cloudflare"

    def test_empty_remainder_returns_none(self) -> None:
        assert waf_detect._parse_wafw00f("example.com is behind \n") is None

    def test_no_match_returns_none(self) -> None:
        assert waf_detect._parse_wafw00f("nothing useful here") is None

    def test_invalid_json_falls_back_to_text(self) -> None:
        assert waf_detect._parse_wafw00f("not json, example.com is behind Sucuri") == "Sucuri"


class TestReadReport:
    def test_missing_file_returns_empty_string(self) -> None:
        assert waf_detect._read_report(Path("definitely-missing.json")) == ""

    def test_reads_existing_file(self, tmp_path: Path) -> None:
        target = tmp_path / "report.json"
        target.write_text("{}", encoding="utf-8")
        assert waf_detect._read_report(target) == "{}"


class TestCandidateUrls:
    def test_https_target_also_probes_http_sibling(self) -> None:
        assert waf_detect._candidate_urls("https://example.com") == ["https://example.com", "http://example.com"]

    def test_http_target_also_probes_https_sibling(self) -> None:
        assert waf_detect._candidate_urls("http://example.com") == ["http://example.com", "https://example.com"]

    def test_bare_host_probes_both_schemes(self) -> None:
        assert waf_detect._candidate_urls("example.com") == ["https://example.com", "http://example.com"]


class _FakeResponse:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


class _FakeAsyncClient:
    """Stand-in for httpx.AsyncClient returning canned response headers."""

    headers: ClassVar[dict[str, str]] = {}
    error: Exception | None = None

    def __init__(self, **kwargs: Any) -> None:
        pass

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get(self, url: str) -> _FakeResponse:
        if type(self).error is not None:
            raise type(self).error
        return _FakeResponse(type(self).headers)


class TestHeaderBlob:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, headers: dict[str, str], error: Exception | None = None) -> None:
        client = type("Client", (_FakeAsyncClient,), {"headers": headers, "error": error})
        fake_httpx = type(
            "FakeHttpx",
            (),
            {"AsyncClient": client, "HTTPError": httpx.HTTPError},
        )
        monkeypatch.setattr(waf_detect, "httpx", fake_httpx)

    def test_joins_headers_into_lowercased_blob(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, {"Server": "cloudflare", "CF-Ray": "abc123"})
        blob = asyncio.run(waf_detect._header_blob("https://example.com"))
        assert blob == "server:cloudflare cf-ray:abc123"

    def test_http_error_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, {}, error=httpx.ConnectError("boom"))
        assert asyncio.run(waf_detect._header_blob("https://example.com")) is None


class TestViaHeaders:
    def test_matches_known_signature(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_blob(url: str) -> str | None:
            return "server:cloudflare cf-ray:xyz"

        monkeypatch.setattr(waf_detect, "_header_blob", fake_blob)
        assert asyncio.run(waf_detect._via_headers(_ctx())) == "Cloudflare"

    def test_signature_matched_on_opposite_scheme_sibling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[str] = []

        async def fake_blob(url: str) -> str | None:
            seen.append(url)
            return "x-sucuri-id:123" if url.startswith("http://") else None

        monkeypatch.setattr(waf_detect, "_header_blob", fake_blob)
        assert asyncio.run(waf_detect._via_headers(_ctx())) == "Sucuri"
        assert seen == ["https://example.com", "http://example.com"]

    def test_no_signatures_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_blob(url: str) -> str | None:
            return "server:nginx date:now"

        monkeypatch.setattr(waf_detect, "_header_blob", fake_blob)
        assert asyncio.run(waf_detect._via_headers(_ctx())) is None

    def test_all_requests_failing_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_blob(url: str) -> str | None:
            return None

        monkeypatch.setattr(waf_detect, "_header_blob", fake_blob)
        assert asyncio.run(waf_detect._via_headers(_ctx())) is None


class TestDetectWaf:
    @staticmethod
    async def _run_and_collect(ctx: ScanContext, bus: EventBus) -> tuple[str | None, list[Any]]:
        # One event loop for emit + drain: asyncio.Queue binds to its first loop.
        name = await waf_detect.detect_waf(ctx, bus)
        await bus.close()
        events: list[Any] = []
        while True:
            event = await bus.next_event()
            if event is None:
                return name, events
            events.append(event)

    def test_waf_found_logs_warning_and_reports_stage(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_wafw00f(ctx: ScanContext) -> str | None:
            return "Cloudflare"

        monkeypatch.setattr(waf_detect, "_via_wafw00f", fake_wafw00f)
        ctx = _ctx(tools={"wafw00f": True})
        name, events = asyncio.run(self._run_and_collect(ctx, EventBus()))

        assert name == "Cloudflare"
        assert isinstance(events[0], StageEvent) and events[0].status is StageStatus.START
        logs = [e for e in events if isinstance(e, LogEvent)]
        assert logs and logs[0].level is LogLevel.WARN and "Cloudflare" in logs[0].message
        done = events[-1]
        assert isinstance(done, StageEvent) and done.status is StageStatus.DONE and done.detail == "Cloudflare"

    def test_no_waf_reports_none_stage_detail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_headers(ctx: ScanContext) -> str | None:
            return None

        monkeypatch.setattr(waf_detect, "_via_headers", fake_headers)
        name, events = asyncio.run(self._run_and_collect(_ctx(), EventBus()))

        assert name is None
        done = events[-1]
        assert isinstance(done, StageEvent) and done.detail == "none"
        assert not any(isinstance(e, LogEvent) for e in events)

    def test_header_fallback_used_when_wafw00f_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[str] = []

        async def fake_headers(ctx: ScanContext) -> str | None:
            called.append("headers")
            return "Akamai"

        async def boom(ctx: ScanContext) -> str | None:  # pragma: no cover - must not run
            called.append("wafw00f")
            return None

        monkeypatch.setattr(waf_detect, "_via_headers", fake_headers)
        monkeypatch.setattr(waf_detect, "_via_wafw00f", boom)
        bus = EventBus()

        name = asyncio.run(waf_detect.detect_waf(_ctx(), bus))  # wafw00f NOT in available_tools
        assert name == "Akamai"
        assert called == ["headers"]


class TestViaWafw00f:
    def test_reads_report_file_written_by_tool(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_run_tool(argv: list[str], options: object) -> ToolResult:
            report = argv[-1]
            with open(report, "w", encoding="utf-8") as handle:
                handle.write('{"detected": true, "firewall": "Imperva"}')
            return ToolResult(tool="wafw00f", returncode=0, stdout="", stderr="")

        monkeypatch.setattr(waf_detect, "run_tool", fake_run_tool)
        assert asyncio.run(waf_detect._via_wafw00f(_ctx())) == "Imperva"

    def test_falls_back_to_stdout_when_report_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_run_tool(argv: list[str], options: object) -> ToolResult:
            return ToolResult(
                tool="wafw00f",
                returncode=0,
                stdout='{"detected": true, "firewall": "Fastly"}',
                stderr="",
            )

        monkeypatch.setattr(waf_detect, "run_tool", fake_run_tool)
        assert asyncio.run(waf_detect._via_wafw00f(_ctx())) == "Fastly"

    def test_empty_output_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def fake_run_tool(argv: list[str], options: object) -> ToolResult:
            return ToolResult(tool="wafw00f", returncode=0, stdout="", stderr="")

        monkeypatch.setattr(waf_detect, "run_tool", fake_run_tool)
        assert asyncio.run(waf_detect._via_wafw00f(_ctx())) is None
