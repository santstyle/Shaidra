"""Tests for severity normalization and ordering.

Every severity payload a tool can emit (label strings, CVSS scores, missing
values) must funnel into the closed ``Severity`` enum predictably — the
renderer, report writers, and dedup tie-breaks all depend on it.
"""

from __future__ import annotations

import math

from shaidra.aggregator.severity import (
    findings_by_severity,
    normalize_severity,
    severity_from_cvss,
)
from shaidra.core.models import Category, Finding, Severity


def _finding(severity: Severity, title: str = "f") -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=Category.WEBVULN,
        host="example.com",
        tool="test",
    )


class TestNormalizeSeverity:
    def test_none_is_unknown(self) -> None:
        assert normalize_severity(None) is Severity.UNKNOWN

    def test_bool_is_unknown_not_a_score(self) -> None:
        assert normalize_severity(True) is Severity.UNKNOWN
        assert normalize_severity(False) is Severity.UNKNOWN

    def test_labels_match_case_insensitively_with_whitespace(self) -> None:
        assert normalize_severity("CRITICAL") is Severity.CRITICAL
        assert normalize_severity("  Crit  ") is Severity.CRITICAL
        assert normalize_severity("High") is Severity.HIGH
        assert normalize_severity("medium") is Severity.MEDIUM
        assert normalize_severity("Moderate") is Severity.MEDIUM
        assert normalize_severity("low") is Severity.LOW
        assert normalize_severity("info") is Severity.INFO
        assert normalize_severity("Informational") is Severity.INFO

    def test_unrecognized_label_is_unknown(self) -> None:
        assert normalize_severity("catastrophic") is Severity.UNKNOWN
        assert normalize_severity("") is Severity.UNKNOWN
        assert normalize_severity("   ") is Severity.UNKNOWN

    def test_numeric_input_read_as_cvss_score(self) -> None:
        assert normalize_severity(9.8) is Severity.CRITICAL
        assert normalize_severity(7.5) is Severity.HIGH
        assert normalize_severity(5.0) is Severity.MEDIUM
        assert normalize_severity(2.0) is Severity.LOW
        assert normalize_severity(0) is Severity.INFO


class TestSeverityFromCvss:
    def test_boundaries_bin_correctly(self) -> None:
        assert severity_from_cvss(9.0) is Severity.CRITICAL
        assert severity_from_cvss(8.9) is Severity.HIGH
        assert severity_from_cvss(7.0) is Severity.HIGH
        assert severity_from_cvss(6.9) is Severity.MEDIUM
        assert severity_from_cvss(4.0) is Severity.MEDIUM
        assert severity_from_cvss(3.9) is Severity.LOW
        assert severity_from_cvss(0.1) is Severity.LOW

    def test_zero_and_negative_scores_are_info(self) -> None:
        assert severity_from_cvss(0.0) is Severity.INFO
        assert severity_from_cvss(-1.0) is Severity.INFO

    def test_non_finite_scores_are_info(self) -> None:
        assert severity_from_cvss(math.nan) is Severity.INFO
        assert severity_from_cvss(math.inf) is Severity.INFO
        assert severity_from_cvss(-math.inf) is Severity.INFO

    def test_score_above_ten_clamps_to_critical(self) -> None:
        assert severity_from_cvss(15.0) is Severity.CRITICAL


class TestFindingsBySeverity:
    def test_orders_most_severe_first(self) -> None:
        findings = [
            _finding(Severity.INFO, "i"),
            _finding(Severity.CRITICAL, "c"),
            _finding(Severity.LOW, "l"),
            _finding(Severity.HIGH, "h"),
            _finding(Severity.UNKNOWN, "u"),
        ]
        ordered = findings_by_severity(findings)
        assert [f.severity for f in ordered] == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.LOW,
            Severity.INFO,
            Severity.UNKNOWN,
        ]

    def test_sort_is_stable_for_equal_severity(self) -> None:
        findings = [_finding(Severity.HIGH, "first"), _finding(Severity.HIGH, "second")]
        ordered = findings_by_severity(findings)
        assert [f.title for f in ordered] == ["first", "second"]

    def test_input_list_is_not_mutated(self) -> None:
        findings = [_finding(Severity.INFO), _finding(Severity.CRITICAL)]
        original = list(findings)
        findings_by_severity(findings)
        assert findings == original

    def test_empty_input(self) -> None:
        assert findings_by_severity([]) == []
