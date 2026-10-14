"""Tests for the misconfig stage: exposure confirmation, severity, base URLs."""

from __future__ import annotations

import asyncio

from shaidra.core.config import Config
from shaidra.core.events import EventBus
from shaidra.core.models import Category, Host, ScanContext, Severity, StageStatus
from shaidra.core.scope import Scope
from shaidra.stages import misconfig


def _ctx(*, web_reachable: bool = True) -> ScanContext:
    ctx = ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.MISCONFIG},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=False,
    )
    ctx.web_reachable = web_reachable
    return ctx


def test_base_url_prefers_host_url() -> None:
    host = Host(host="example.com", url="https://example.com/")
    assert misconfig._base_url(host) == "https://example.com"


def test_base_url_uses_scheme_and_port() -> None:
    host = Host(host="example.com", port=8080, scheme="http")
    assert misconfig._base_url(host) == "http://example.com:8080"


def test_base_url_default_ports_omit_port() -> None:
    assert misconfig._base_url(Host(host="example.com", port=443, scheme="https")) == "https://example.com"


def test_in_scope_bases_empty_when_nothing_live() -> None:
    assert misconfig._in_scope_bases(_ctx()) == ["https://example.com"]


def test_severity_for_path_high_medium_low() -> None:
    assert misconfig._severity_for_path(".git/config") is Severity.HIGH
    assert misconfig._severity_for_path(".env") is Severity.HIGH
    assert misconfig._severity_for_path("config.json") is Severity.MEDIUM
    assert misconfig._severity_for_path(".env.example") is Severity.LOW


def test_confirmed_requires_status_200_and_body() -> None:
    assert misconfig._confirmed(".env", 404, b"SECRET=1", "text/plain") is False
    assert misconfig._confirmed(".env", 200, b"", "text/plain") is False


def test_confirmed_git_config_and_head() -> None:
    assert misconfig._confirmed(".git/config", 200, b"[core]\n", "text/plain") is True
    assert misconfig._confirmed(".git/HEAD", 200, b"ref: refs/heads/main\n", "text/plain") is True
    assert misconfig._confirmed(".git/config", 200, b"<html>404</html>", "text/html") is False


def test_confirmed_env_file_line() -> None:
    assert misconfig._confirmed(".env", 200, b"API_KEY=abc123\n", "text/plain") is True
    assert misconfig._confirmed(".env", 200, b"<!doctype html>", "text/html") is False


def test_confirmed_dockerfile_and_config_json() -> None:
    assert misconfig._confirmed("Dockerfile", 200, b"FROM alpine\n", "text/plain") is True
    assert misconfig._confirmed("config.json", 200, b'{"a": 1}', "application/json") is True


def _drain(bus: EventBus) -> list[object]:
    async def scenario() -> list[object]:
        await bus.close()
        events: list[object] = []
        while True:
            event = await bus.next_event()
            if event is None:
                return events
            events.append(event)

    return asyncio.run(scenario())


def test_run_skips_when_not_reachable() -> None:
    bus = EventBus()
    asyncio.run(misconfig.run(_ctx(web_reachable=False), bus))
    events = _drain(bus)
    statuses = [getattr(e, "status", None) for e in events]
    assert StageStatus.SKIP in statuses


def test_run_skips_without_live_hosts_outside_scope() -> None:
    ctx = ScanContext(
        target="other.com",
        target_url="https://other.com",
        mode="quick",
        categories={Category.MISCONFIG},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=False,
    )
    ctx.web_reachable = True
    bus = EventBus()
    asyncio.run(misconfig.run(ctx, bus))
    events = _drain(bus)
    statuses = [getattr(e, "status", None) for e in events]
    assert StageStatus.SKIP in statuses


def test_testssl_bin_absent() -> None:
    assert misconfig._testssl_bin(_ctx()) is None
