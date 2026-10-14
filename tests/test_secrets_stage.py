"""Tests for secrets stage helpers: asset extraction and target selection."""

from __future__ import annotations

from shaidra.core.config import Config
from shaidra.core.models import Category, ScanContext
from shaidra.core.scope import Scope
from shaidra.stages import secrets


def _ctx(crawled: list[str] | None = None) -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.SECRETS},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=False,
        crawled_urls=crawled or [],
    )


def test_scan_targets_includes_target_and_crawled() -> None:
    ctx = _ctx(["https://example.com/a", "https://example.com/b"])
    urls = secrets._scan_targets(ctx)
    assert urls[0] == "https://example.com"
    assert "https://example.com/a" in urls
    assert "https://example.com/b" in urls


def test_scan_targets_excludes_out_of_scope() -> None:
    ctx = _ctx(["https://evil.com/x"])
    urls = secrets._scan_targets(ctx)
    assert urls == ["https://example.com"]


def test_scan_targets_strips_fragment() -> None:
    ctx = _ctx(["https://example.com/page#section"])
    urls = secrets._scan_targets(ctx)
    assert "https://example.com/page" in urls


def test_extract_assets_finds_script_and_json() -> None:
    body = '<script src="/app.js"></script><link href="/style.css"><a href="/data.json">x</a>'
    ctx = _ctx()
    assets = secrets._extract_assets("https://example.com/page", body, ctx, set())
    assert "https://example.com/app.js" in assets
    assert "https://example.com/data.json" in assets
    assert not any(u.endswith("style.css") for u in assets)


def test_extract_assets_skips_hash_and_mailto() -> None:
    body = '<a href="#top">x</a><a href="mailto:a@b.c">y</a><a href="javascript:void(0)">z</a>'
    ctx = _ctx()
    assert secrets._extract_assets("https://example.com/", body, ctx, set()) == []


def test_extract_assets_dedup_via_seen() -> None:
    body = '<script src="/app.js"></script>'
    ctx = _ctx()
    seen = {"https://example.com/app.js"}
    assert secrets._extract_assets("https://example.com/", body, ctx, seen) == []


def test_is_text_content_types() -> None:
    assert secrets._is_text("text/html")
    assert secrets._is_text("application/json")
    assert secrets._is_text("application/javascript")
    assert secrets._is_text("")
    assert not secrets._is_text("image/png")
    assert not secrets._is_text("application/pdf")
