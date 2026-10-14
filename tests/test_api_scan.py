"""Tests for API scan confirmation and kiterunner parsing."""

from __future__ import annotations

from shaidra.core.models import Category, Severity
from shaidra.stages import api_scan
from shaidra.stages.api_scan import _Probe


def test_confirmed_marker_in_body() -> None:
    probe = _Probe(
        path="/swagger.json",
        title="Exposed API documentation (Swagger)",
        severity=Severity.MEDIUM,
        markers=("swagger", "openapi"),
    )
    assert api_scan._confirmed("this is swagger", "application/json", probe) is True
    assert api_scan._confirmed("nothing", "text/html", probe) is False


def test_confirmed_json_content_type() -> None:
    probe = _Probe(path="/api", title="API root reachable", severity=Severity.INFO, markers=())
    assert api_scan._confirmed("{}", "application/json", probe) is True
    assert api_scan._confirmed("[1]", "text/plain", probe) is True
    assert api_scan._confirmed("plain text", "text/plain", probe) is False


def test_kr_finding_parses_route() -> None:
    line = '{"URL": "/api/users", "Method": "GET", "Status": 200}'
    finding = api_scan._kr_finding(line, "https://example.com")
    assert finding is not None
    assert finding.url == "https://example.com/api/users"
    assert finding.severity is Severity.INFO
    assert finding.category is Category.API
    assert finding.tool == "kiterunner"


def test_kr_finding_rejects_junk() -> None:
    assert api_scan._kr_finding("not-json", "https://example.com") is None
    assert api_scan._kr_finding('{"no": "route"}', "https://example.com") is None


def test_kr_finding_absolute_url() -> None:
    line = '{"url": "https://other.example/path", "method": "POST"}'
    finding = api_scan._kr_finding(line, "https://example.com")
    assert finding is not None
    assert finding.url == "https://other.example/path"


def test_host_of() -> None:
    assert api_scan._host_of("https://example.com/x") == "example.com"
    assert api_scan._host_of("nope") == "nope"


def test_text_and_int_helpers() -> None:
    assert api_scan._text("x") == "x"
    assert api_scan._text(1) == ""
    assert api_scan._int(5) == 5
    assert api_scan._int("5") is None
    assert api_scan._int(None) is None
