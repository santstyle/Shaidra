"""Tests for CORS verdict classification, severity, and finding assembly."""

from __future__ import annotations

from shaidra.core.models import Host, Severity
from shaidra.stages import cors
from shaidra.stages.cors import CorsVerdict, _ProbeResult


def test_classify_no_acao_is_safe() -> None:
    assert cors._classify("https://evil.example", None, None) is CorsVerdict.SAFE


def test_classify_reflect_with_credentials() -> None:
    verdict = cors._classify("https://evil.example", "https://evil.example", "true")
    assert verdict is CorsVerdict.REFLECT_WITH_CREDS


def test_classify_wildcard_with_credentials() -> None:
    assert cors._classify("https://evil.example", "*", "true") is CorsVerdict.REFLECT_WITH_CREDS


def test_classify_reflect_without_credentials() -> None:
    assert cors._classify("https://evil.example", "https://evil.example", None) is CorsVerdict.REFLECT_NO_CREDS


def test_classify_null_origin_reflection() -> None:
    assert cors._classify("null", "null", None) is CorsVerdict.NULL_REFLECTION
    assert cors._classify("null", "*", "true") is CorsVerdict.SAFE


def test_classify_fixed_allowlist_is_safe() -> None:
    assert cors._classify("https://evil.example", "https://ok.example", None) is CorsVerdict.SAFE


def test_severity_for_verdicts() -> None:
    assert cors._severity_for(CorsVerdict.REFLECT_WITH_CREDS) is Severity.HIGH
    assert cors._severity_for(CorsVerdict.REFLECT_NO_CREDS) is Severity.MEDIUM
    assert cors._severity_for(CorsVerdict.NULL_REFLECTION) is Severity.LOW
    assert cors._severity_for(CorsVerdict.SAFE) is Severity.INFO


def test_rank_orders_worst_first() -> None:
    high = _ProbeResult("https://evil.example", "https://evil.example", "true", CorsVerdict.REFLECT_WITH_CREDS)
    low = _ProbeResult("null", "null", None, CorsVerdict.NULL_REFLECTION)
    assert cors._rank(high) > cors._rank(low)


def test_format_headers_and_finding() -> None:
    result = _ProbeResult("https://evil.example", "https://evil.example", "true", CorsVerdict.REFLECT_WITH_CREDS)
    host = Host(host="example.com", url="https://example.com")
    finding = cors._build_finding(host, result)
    assert finding.severity is Severity.HIGH
    assert finding.category is cors.Category.CORS
    assert "evil.example" in finding.evidence
    assert finding.raw["verdict"] == "reflect_with_creds"
