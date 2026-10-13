"""End-to-end test for the built-in web-vuln fallback (no nuclei/dalfox).

Exercises the parallelised detector dispatch in ``_builtin_fallback`` against a
local fixture that reflects the XSS marker verbatim, and checks the
context-aware classifier still raises a HIGH finding for it.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from shaidra.core.config import Config
from shaidra.core.events import EventBus, FindingEvent
from shaidra.core.models import Category, Finding, ScanContext, Severity
from shaidra.core.scope import Scope
from shaidra.stages import webvuln

_REFLECTION_MARKER = "sdrq<u>z9</u>k"


class _ReflectingHandler(BaseHTTPRequestHandler):
    """Echo the ``q`` parameter verbatim only when it carries the XSS marker."""

    def _respond(self, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        params = parse_qs(urlparse(self.path).query)
        value = params.get("q", [""])[0]
        if _REFLECTION_MARKER in value:
            self._respond(f"<html><body><p>{value}</p></body></html>")
        else:
            self._respond("<html><body>static page</body></html>")

    def do_POST(self) -> None:
        self._respond("<html><body>static page</body></html>")

    def log_message(self, *args: object) -> None:  # silence the default logger
        return


@pytest.fixture()
def reflecting_server() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ReflectingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


async def _run_builtin(target_url: str) -> list[Finding]:
    ctx = ScanContext(
        target="127.0.0.1",
        target_url=f"{target_url}/?q=1",
        mode="quick",
        categories={Category.WEBVULN},
        rate_limit=200,
        extended=False,
        scope=Scope(("127.0.0.1",)),
        config=Config(),
        web_reachable=True,
    )
    ctx.crawled_urls = [f"{target_url}/?q=1"]
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
    # available_tools stays empty, so run() takes the built-in fallback path.
    await webvuln.run(ctx, bus)
    await bus.close()
    await consumer
    return collected


def test_builtin_reflection_flags_unescaped_marker(
    reflecting_server: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _noop(*args: object, **kwargs: object) -> int:
        return 0

    async def _no_oob(*args: object, **kwargs: object) -> None:
        return None

    # Skip the slow time-based SQLi sweep and the OOB listener bind; the
    # reflection detector and the concurrent dispatch are what this test covers.
    monkeypatch.setattr(webvuln, "_own_sqli", _noop)
    monkeypatch.setattr(webvuln, "_start_oob", _no_oob)

    findings = asyncio.run(_run_builtin(reflecting_server))
    high = [finding for finding in findings if finding.severity is Severity.HIGH]
    assert high, f"expected a HIGH reflected-XSS finding, got {[f.title for f in findings]}"
    assert all(finding.category is Category.WEBVULN for finding in high)
    assert any(finding.tool == "shaidra" for finding in high)
