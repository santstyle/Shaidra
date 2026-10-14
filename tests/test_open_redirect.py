"""Tests for open-redirect probe building and Location validation."""

from __future__ import annotations

from shaidra.core.config import Config
from shaidra.core.models import Category, ScanContext
from shaidra.core.scope import Scope
from shaidra.stages import open_redirect
from shaidra.stages.open_redirect import _Probe


def _ctx(crawled: list[str] | None = None) -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.REDIRECT},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=False,
        crawled_urls=crawled or [],
    )


def test_points_external_accepts_https_and_protocol_relative() -> None:
    assert open_redirect._points_external("https://evil.example/") is True
    assert open_redirect._points_external("//evil.example/x") is True


def test_points_external_rejects_same_host_and_empty() -> None:
    assert open_redirect._points_external("https://example.com/ok") is False
    assert open_redirect._points_external("") is False
    assert open_redirect._points_external("  ") is False


def test_build_probes_uses_crawled_query_urls() -> None:
    ctx = _ctx(["https://example.com/login?next=https://ok.example"])
    probes = open_redirect._build_probes(ctx)
    assert probes
    assert any(p.param.lower() == "next" for p in probes)


def test_build_probes_fallback_from_base_url() -> None:
    ctx = _ctx([])
    probes = open_redirect._build_probes(ctx)
    assert probes
    assert probes[0].endpoint == "https://example.com"
    assert probes[0].marker.startswith("https://evil.example")


def test_build_finding_sets_category_and_raw() -> None:
    probe = _Probe(
        "https://example.com/?url=https://evil.example/", "https://example.com", "url", "https://evil.example/"
    )
    finding = open_redirect._build_finding(probe, "https://evil.example/")
    assert finding.severity.name == "MEDIUM"
    assert finding.raw["param"] == "url"
    assert finding.host == "example.com"
