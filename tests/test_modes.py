"""Tests for scan modes: `--mode deep` coverage scaling and `--extended` budgets."""

from __future__ import annotations

from shaidra.core.config import Config
from shaidra.core.models import Category, ScanContext
from shaidra.core.scope import Scope
from shaidra.stages.content_discovery import _content_budget
from shaidra.stages.webvuln import _Probe, _select_probes


def _ctx(mode: str, *, extended: bool = False) -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode=mode,
        categories={Category.RECON},
        rate_limit=40,
        extended=extended,
        scope=Scope(("example.com",)),
        config=Config(),
    )


def test_deep_property_tracks_mode() -> None:
    assert _ctx("deep").deep is True
    assert _ctx("quick").deep is False


def test_scale_selects_budget_by_mode() -> None:
    assert _ctx("quick").scale(700, 3000) == 700
    assert _ctx("deep").scale(700, 3000) == 3000


def test_content_budget_grows_with_deep_mode() -> None:
    assert _content_budget(_ctx("quick"), 5000) == 700
    assert _content_budget(_ctx("deep"), 5000) == 3000


def test_content_budget_uses_full_list_when_extended() -> None:
    assert _content_budget(_ctx("quick", extended=True), 5000) == 5000


def test_select_probes_respects_cap() -> None:
    probes = [_Probe(method="GET", url=f"https://example.com/?p{i}=", param=f"p{i}", fields={}) for i in range(10)]
    assert len(_select_probes(probes, cap=3)) == 3
    assert len(_select_probes(probes)) == 10
