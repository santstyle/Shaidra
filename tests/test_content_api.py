"""Tests for content-discovery helpers: sensitivity, catch-all, tool parsers, findings."""

from __future__ import annotations

import asyncio
import json

from shaidra.core.config import Config
from shaidra.core.events import EventBus
from shaidra.core.models import Category, Host, ScanContext, Severity
from shaidra.core.scope import Scope
from shaidra.stages import content_discovery
from shaidra.stages.content_discovery import _Baseline, _Hit


def _ctx() -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.CONTENT},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=False,
    )


def test_sensitivity_tiers() -> None:
    assert content_discovery._sensitivity("/.git/config") is Severity.HIGH
    assert content_discovery._sensitivity("/backup.sql") is Severity.HIGH
    assert content_discovery._sensitivity("/admin/login") is Severity.MEDIUM
    assert content_discovery._sensitivity("/metrics") is Severity.LOW
    assert content_discovery._sensitivity("/index.html") is None
    assert content_discovery._sensitivity("/ADMIN/DASH") is Severity.MEDIUM


def test_clamp_by_status_downgrades_redirects() -> None:
    assert content_discovery._clamp_by_status(Severity.HIGH, 301) is Severity.LOW
    assert content_discovery._clamp_by_status(Severity.MEDIUM, 302) is Severity.LOW
    assert content_discovery._clamp_by_status(Severity.LOW, 307) is Severity.LOW
    assert content_discovery._clamp_by_status(Severity.HIGH, 200) is Severity.HIGH
    assert content_discovery._clamp_by_status(Severity.MEDIUM, 403) is Severity.MEDIUM


def test_is_text_content_types() -> None:
    assert content_discovery._is_text("application/json") is True
    assert content_discovery._is_text("text/html; charset=utf-8") is True
    assert content_discovery._is_text("image/png") is False
    assert content_discovery._is_text("") is False


def test_netloc_lowercases() -> None:
    assert content_discovery._netloc("https://Example.com:8443/path") == "example.com:8443"


def test_host_base_prefers_url_then_builds_from_parts() -> None:
    with_url = Host(host="example.com", url="https://example.com/")
    assert content_discovery._host_base(with_url) == "https://example.com"
    with_port = Host(host="example.com", port=8080, scheme="http")
    assert content_discovery._host_base(with_port) == "http://example.com:8080"
    default_port = Host(host="example.com", port=443, scheme="https")
    assert content_discovery._host_base(default_port) == "https://example.com"


def test_type_family() -> None:
    assert content_discovery._type_family("text/html") == "html"
    assert content_discovery._type_family("application/json") == "json"
    assert content_discovery._type_family("application/xml") == "xml"
    assert content_discovery._type_family("text/javascript") == "javascript"
    assert content_discovery._type_family("text/plain") == "text"
    assert content_discovery._type_family("") == "text"


def test_squash_collapses_whitespace() -> None:
    assert content_discovery._squash("  a \n\t b  ") == "a b"


def test_looks_like_catch_all_same_body() -> None:
    baseline = _Baseline(status=200, body="<html>app</html>", ctype="text/html")
    hit = _Hit(url="u", status=200, length=1, tool="t", body="<html>app</html>", ctype="text/html")
    assert content_discovery._looks_like_catch_all(hit, baseline) is True


def test_looks_like_catch_all_status_mismatch() -> None:
    baseline = _Baseline(status=200, body="<html>app</html>", ctype="text/html")
    hit = _Hit(url="u", status=404, length=1, tool="t", body="<html>app</html>", ctype="text/html")
    assert content_discovery._looks_like_catch_all(hit, baseline) is False


def test_looks_like_catch_all_type_family_mismatch() -> None:
    baseline = _Baseline(status=200, body="{}", ctype="application/json")
    hit = _Hit(url="u", status=200, length=1, tool="t", body="{}", ctype="text/html")
    assert content_discovery._looks_like_catch_all(hit, baseline) is False


def test_looks_like_catch_all_near_identical_long_bodies() -> None:
    shared = "x" * 250
    baseline = _Baseline(status=200, body=shared + "AAAA", ctype="text/html")
    hit = _Hit(url="u", status=200, length=1, tool="t", body=shared + "BBBB", ctype="text/html")
    assert content_discovery._looks_like_catch_all(hit, baseline) is True


def test_as_int_accepts_int_and_digit_str_rejects_bool() -> None:
    assert content_discovery._as_int(5) == 5
    assert content_discovery._as_int("42") == 42
    assert content_discovery._as_int("-7") == -7
    assert content_discovery._as_int(True) is None
    assert content_discovery._as_int("x") is None
    assert content_discovery._as_int(None) is None


def test_hit_from_maps_entry() -> None:
    hit = content_discovery._hit_from(
        {"url": "https://x/a", "status": 200, "content_length": 42},
        "feroxbuster",
    )
    assert hit is not None
    assert hit.url == "https://x/a"
    assert hit.status == 200
    assert hit.length == 42
    assert hit.tool == "feroxbuster"
    hit2 = content_discovery._hit_from({"url": "https://x/b", "status": "200", "length": "7"}, "ffuf")
    assert hit2 is not None
    assert hit2.status == 200
    assert hit2.length == 7


def test_hit_from_rejects_missing_fields() -> None:
    assert content_discovery._hit_from({"status": 200}, "t") is None
    assert content_discovery._hit_from({"url": "https://x/"}, "t") is None
    assert content_discovery._hit_from({"url": "https://x/", "status": True}, "t") is None


def test_ferox_line_parses_json() -> None:
    line = json.dumps({"url": "https://x/b", "status": 403, "content_length": 5})
    hit = content_discovery._ferox_line(line)
    assert hit is not None
    assert hit.tool == "feroxbuster"
    assert hit.status == 403
    assert content_discovery._ferox_line("nope") is None
    assert content_discovery._ferox_line("[]") is None


def test_ffuf_stdout_parses_results() -> None:
    stdout = json.dumps({"results": [{"url": "https://x/c", "status": 200, "length": 10}]})
    hits = content_discovery._ffuf_stdout(stdout)
    assert len(hits) == 1
    assert hits[0].tool == "ffuf"
    assert hits[0].length == 10
    assert content_discovery._ffuf_stdout("not json") == []
    assert content_discovery._ffuf_stdout('{"nope": []}') == []
    assert content_discovery._ffuf_stdout('{"results": "x"}') == []


def test_content_budget_quick_deep_extended() -> None:
    ctx = _ctx()
    assert content_discovery._content_budget(ctx, 1000) == content_discovery._OWN_BUDGET
    ctx.mode = "deep"
    assert content_discovery._content_budget(ctx, 5000) == content_discovery._OWN_BUDGET_DEEP
    ctx.extended = True
    assert content_discovery._content_budget(ctx, 5000) == 5000
    assert content_discovery._content_budget(ctx, 100) == 100


def test_describe_severity_strings() -> None:
    assert "high-value" in content_discovery._describe(Severity.HIGH)
    assert "administrative" in content_discovery._describe(Severity.MEDIUM)
    assert "manual review" in content_discovery._describe(Severity.LOW)


def test_wordlist_lines_and_entries(tmp_path) -> None:
    wordlist = tmp_path / "w.txt"
    wordlist.write_text("# c\na\n\nb\n", encoding="utf-8")
    assert content_discovery._wordlist_lines(wordlist) == ["# c", "a", "", "b"]
    assert content_discovery._wordlist_entries(wordlist) == 2


def test_probe_bases_from_live_hosts() -> None:
    ctx = _ctx()
    ctx.add_host(Host(host="example.com", url="https://example.com", is_live=True))
    ctx.add_host(Host(host="dead.example.com", url="https://dead.example.com", is_live=False))
    assert content_discovery._probe_bases(ctx) == ["https://example.com"]


def test_emit_findings_secret_and_path() -> None:
    async def scenario() -> int:
        bus = EventBus()
        ctx = _ctx()
        hit = _Hit(
            url="https://example.com/admin/login",
            status=200,
            length=100,
            tool="feroxbuster",
            body="key=AKIABBBBBBBBBBBBBBBB",
            ctype="text/html",
        )
        emitted = await content_discovery._emit_findings(ctx, bus, [hit], {})
        await bus.close()
        return emitted

    assert asyncio.run(scenario()) == 2


def test_emit_findings_skips_known_exposure_and_catch_all() -> None:
    async def scenario() -> int:
        bus = EventBus()
        ctx = _ctx()
        known = _Hit(url="https://example.com/.env", status=200, length=1, tool="t")
        catch_hit = _Hit(
            url="https://example.com/whatever",
            status=200,
            length=1,
            tool="t",
            body="<html>app</html>",
            ctype="text/html",
        )
        baseline = _Baseline(status=200, body="<html>app</html>", ctype="text/html")
        emitted = await content_discovery._emit_findings(ctx, bus, [known, catch_hit], {"example.com": baseline})
        await bus.close()
        return emitted

    assert asyncio.run(scenario()) == 0


def test_emit_findings_clamps_redirect_severity() -> None:
    async def scenario() -> list[str]:
        bus = EventBus()
        ctx = _ctx()
        hit = _Hit(url="https://example.com/backup-old", status=301, length=0, tool="t")
        await content_discovery._emit_findings(ctx, bus, [hit], {})
        await bus.close()
        severities: list[str] = []
        while True:
            event = await bus.next_event()
            if event is None:
                return severities
            finding = getattr(event, "finding", None)
            if finding is not None:
                severities.append(finding.severity.value)

    assert asyncio.run(scenario()) == ["low"]
