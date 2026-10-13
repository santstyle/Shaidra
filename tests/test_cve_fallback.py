"""Integration test for the built-in CVE fallback stage (nuclei absent)."""

from __future__ import annotations

import asyncio

from shaidra.core.config import Config
from shaidra.core.events import EventBus, FindingEvent
from shaidra.core.models import Category, Finding, Host, ScanContext
from shaidra.core.scope import Scope
from shaidra.stages import cve_match


def _context() -> ScanContext:
    target = "http://example.com"
    ctx = ScanContext(
        target="example.com",
        target_url=target,
        mode="quick",
        categories={Category.CVE},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
    )
    # available_tools stays empty, so has_tool("nuclei") is False and the
    # built-in table runs instead of nuclei.
    ctx.add_host(Host(host="example.com", url=target, is_live=True, tech=["Apache/2.4.49 (Ubuntu)"]))
    ctx.add_host(
        Host(host="safe.example.com", url="http://safe.example.com", is_live=True, tech=["nginx/1.24.0"])
    )
    return ctx


async def _run_fallback() -> list[Finding]:
    ctx = _context()
    bus = EventBus()
    collected: list[Finding] = []

    async def consume() -> None:
        while True:
            event = await bus.next_event()
            if event is None:
                break
            if isinstance(event, FindingEvent):
                collected.append(event.finding)

    consumer = asyncio.create_task(consume())
    await cve_match.run(ctx, bus)
    await bus.close()
    await consumer
    return collected


def test_builtin_fallback_flags_vulnerable_host_only() -> None:
    findings = asyncio.run(_run_fallback())
    assert findings, "expected the built-in table to raise at least one finding"
    assert {finding.cve for finding in findings} == {"CVE-2021-41773"}
    assert {finding.host for finding in findings} == {"example.com"}
    assert all(finding.category is Category.CVE for finding in findings)
    assert all(finding.tool == "shaidra" for finding in findings)
