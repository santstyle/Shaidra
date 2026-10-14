"""Tests for the CMS fingerprint classifier and helper paths."""

from __future__ import annotations

import asyncio

from shaidra.core.config import Config
from shaidra.core.events import EventBus
from shaidra.core.models import Category, ScanContext, StageStatus
from shaidra.core.scope import Scope
from shaidra.stages import cms_scan
from shaidra.stages.cms_scan import Cms


def _ctx() -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.CMS},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=False,
    )


def test_classify_wordpress_from_body_markers() -> None:
    assert cms_scan._classify("/wp-content/themes/x", "", "") == {Cms.WORDPRESS}
    assert cms_scan._classify(" /wp-json/wp/v2/users", "", "") == {Cms.WORDPRESS}


def test_classify_wordpress_from_generator_header() -> None:
    # _fingerprint lowercases headers before _classify; generator match is case-sensitive
    assert cms_scan._classify("", "wordpress 6.4", "") == {Cms.WORDPRESS}


def test_classify_drupal_from_body_and_headers() -> None:
    assert cms_scan._classify("/sites/default/files/logo.png", "", "") == {Cms.DRUPAL}
    assert cms_scan._classify("", "drupal 10", "") == {Cms.DRUPAL}
    assert cms_scan._classify("", "", "drupal 10") == {Cms.DRUPAL}


def test_classify_joomla() -> None:
    assert cms_scan._classify("option=com_content", "", "") == {Cms.JOOMLA}
    assert cms_scan._classify("/media/jui/css/template.css", "", "") == {Cms.JOOMLA}


def test_classify_magento_requires_marker_pair() -> None:
    assert cms_scan._classify("magento", "", "") == set()
    assert cms_scan._classify("magento data-mage-init", "", "") == {Cms.MAGENTO}


def test_classify_empty_body_returns_empty() -> None:
    assert cms_scan._classify("", "", "") == set()


def test_targets_cap_and_dedup() -> None:
    ctx = _ctx()
    assert cms_scan._targets(ctx) == ["https://example.com"]


def test_host_of_extracts_hostname() -> None:
    assert cms_scan._host_of("https://example.com/path") == "example.com"


def test_first_version_parses_wordpress_readme() -> None:
    assert cms_scan._first_version("Version 6.4.2") == "6.4.2"
    assert cms_scan._first_version("no version here") == ""


def test_user_slugs_parses_rest_payload() -> None:
    body = '[{"slug": "admin"}, {"slug": "editor"}, {"id": 1}]'
    assert cms_scan._user_slugs(body) == ["admin", "editor"]
    assert cms_scan._user_slugs("not-json") == []
    assert cms_scan._user_slugs('{"slug": "x"}') == []


def test_load_object_and_text() -> None:
    assert cms_scan._load_object('{"a": 1}') == {"a": 1}
    assert cms_scan._load_object("[1]") is None
    assert cms_scan._text("x") == "x"
    assert cms_scan._text(1) == ""


def test_first_cve_from_references() -> None:
    assert cms_scan._first_cve({"cve": ["CVE-2021-1234"]}) == "CVE-2021-1234"
    assert cms_scan._first_cve({"cve": "CVE-2020-9999"}) == "CVE-2020-9999"
    assert cms_scan._first_cve({"cve": []}) is None
    assert cms_scan._first_cve(None) is None


def test_detected_finding_shape() -> None:
    finding = cms_scan._detected_finding("https://example.com", {Cms.WORDPRESS})
    assert finding.severity.name == "INFO"
    assert finding.category is Category.CMS
    assert finding.raw["cms"] == ["WordPress"]


def test_run_skips_when_not_reachable() -> None:
    async def scenario() -> list[object]:
        bus = EventBus()
        ctx = _ctx()
        ctx.web_reachable = False
        await cms_scan.run(ctx, bus)
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
