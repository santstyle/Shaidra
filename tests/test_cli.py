"""Tests for CLI pure helpers: headers, overrides, categories, stream hardening."""

from __future__ import annotations

from shaidra.cli import _apply_overrides, _harden_streams, _make_console, _parse_categories, _request_headers
from shaidra.core.config import Config
from shaidra.core.models import ALL_CATEGORIES, Category


def test_request_headers_merges_cookie_and_headers() -> None:
    merged = _request_headers("sid=1", ["X-Api-Key: abc", "Authorization: Bearer t"])
    assert merged["Cookie"] == "sid=1"
    assert merged["X-Api-Key"] == "abc"
    assert merged["Authorization"] == "Bearer t"


def test_request_headers_skips_malformed() -> None:
    assert _request_headers(None, ["no-colon", ":empty-name", "  :  "]) == {}


def test_apply_overrides_none_leaves_config() -> None:
    config = Config()
    assert _apply_overrides(config, rate_limit=None, threads=None, mode=None) is config


def test_apply_overrides_sets_fields() -> None:
    config = Config()
    updated = _apply_overrides(config, rate_limit=5, threads=8, mode="Deep")
    assert updated.rate_limit == 5
    assert updated.ffuf_threads == 8
    assert updated.mode == "deep"


def test_parse_categories_default_all() -> None:
    assert _parse_categories(None) == set(ALL_CATEGORIES)
    assert _parse_categories("  ") == set(ALL_CATEGORIES)


def test_parse_categories_subset() -> None:
    assert _parse_categories("recon,cors") == {Category.RECON, Category.CORS}


def test_parse_categories_rejects_unknown() -> None:
    import typer

    try:
        _parse_categories("nope")
    except typer.BadParameter as exc:
        assert "nope" in str(exc)
    else:
        raise AssertionError("expected BadParameter")


def test_parse_categories_empty_tokens_ignored() -> None:
    assert _parse_categories("recon,,cors,") == {Category.RECON, Category.CORS}


def test_harden_streams_smoke() -> None:
    _harden_streams()


def test_make_console_non_tty_is_plain() -> None:
    console = _make_console()
    assert console.no_color is True
    assert console.legacy_windows is False
