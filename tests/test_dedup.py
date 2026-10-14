"""Tests for cross-tool duplicate collapsing of findings.

Identity comes from WHAT and WHERE a problem is; the producing tool,
severity, evidence, and timestamp are excluded so duplicate reports of one
issue merge while genuinely different bugs on a shared URL both survive.
"""

from __future__ import annotations

from shaidra.aggregator.dedup import dedup_findings, finding_key
from shaidra.core.models import Category, Finding, Severity


def _finding(
    *,
    title: str = "Exposed .git directory",
    severity: Severity = Severity.MEDIUM,
    category: Category = Category.MISCONFIG,
    host: str = "example.com",
    tool: str = "stage-a",
    evidence: str = "",
    description: str = "",
    url: str | None = "https://example.com/.git/",
    reference: str | None = None,
    template: str | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        host=host,
        tool=tool,
        evidence=evidence,
        description=description,
        url=url,
        reference=reference,
        template=template,
    )


class TestFindingKey:
    def test_exposure_categories_key_by_url_alone(self) -> None:
        for category in (Category.MISCONFIG, Category.CONTENT, Category.API):
            first = finding_key(_finding(category=category, tool="a", host="x.example"))
            second = finding_key(_finding(category=category, tool="b", host="other.example", title="totally different"))
            assert first == second == ("url", "https://example.com/.git", "", "", ""), category

    def test_exposure_url_trailing_slash_and_case_ignored(self) -> None:
        a = finding_key(_finding(url="https://example.com/Admin"))
        b = finding_key(_finding(url="https://EXAMPLE.com/admin/"))
        assert a == b

    def test_exposure_without_url_falls_back_to_full_identity(self) -> None:
        key = finding_key(_finding(url=None))
        assert key[0] == Category.MISCONFIG.value

    def test_vulnerability_categories_keep_full_identity(self) -> None:
        xss = finding_key(_finding(category=Category.WEBVULN, title="Reflected XSS", url="https://example.com/q"))
        sqli = finding_key(_finding(category=Category.WEBVULN, title="SQL injection", url="https://example.com/q"))
        assert xss != sqli

    def test_same_title_different_urls_are_distinct(self) -> None:
        a = finding_key(_finding(category=Category.WEBVULN, url="https://example.com/a"))
        b = finding_key(_finding(category=Category.WEBVULN, url="https://example.com/b"))
        assert a != b

    def test_host_and_title_are_casefolded_and_stripped(self) -> None:
        a = finding_key(_finding(category=Category.WEBVULN, host=" Example.COM ", title="  Reflected XSS "))
        b = finding_key(_finding(category=Category.WEBVULN, host="example.com", title="reflected xss"))
        assert a == b

    def test_template_and_reference_fill_the_last_slot(self) -> None:
        with_template = finding_key(_finding(category=Category.WEBVULN, template="cve-2024-1"))
        with_reference = finding_key(_finding(category=Category.WEBVULN, reference="CWE-79"))
        neither = finding_key(_finding(category=Category.WEBVULN))
        assert with_template[-1] == "cve-2024-1"
        assert with_reference[-1] == "CWE-79"
        assert neither[-1] == ""


class TestDedupFindings:
    def test_duplicates_collapse_to_single_finding(self) -> None:
        findings = [
            _finding(tool="stage-a"),
            _finding(tool="stage-b", severity=Severity.HIGH),
        ]
        result = dedup_findings(findings)
        assert len(result) == 1
        assert result[0].severity is Severity.HIGH

    def test_distinct_findings_are_all_kept(self) -> None:
        findings = [
            _finding(category=Category.WEBVULN, title="XSS", url="https://example.com/q"),
            _finding(category=Category.WEBVULN, title="SQLi", url="https://example.com/q"),
            _finding(category=Category.MISCONFIG, url="https://example.com/.env"),
        ]
        assert len(dedup_findings(findings)) == 3

    def test_higher_severity_wins_over_first_seen(self) -> None:
        findings = [
            _finding(severity=Severity.LOW, evidence="thin"),
            _finding(severity=Severity.CRITICAL, evidence="thin"),
        ]
        result = dedup_findings(findings)
        assert result[0].severity is Severity.CRITICAL

    def test_equal_severity_prefers_richer_detail(self) -> None:
        findings = [
            _finding(severity=Severity.HIGH, evidence="", description=""),
            _finding(severity=Severity.HIGH, evidence="full response body captured here"),
        ]
        result = dedup_findings(findings)
        assert result[0].evidence == "full response body captured here"

    def test_full_tie_keeps_first_seen(self) -> None:
        findings = [
            _finding(severity=Severity.HIGH, tool="first-seen"),
            _finding(severity=Severity.HIGH, tool="second-seen"),
        ]
        result = dedup_findings(findings)
        assert result[0].tool == "first-seen"

    def test_result_preserves_first_seen_key_order(self) -> None:
        findings = [
            _finding(category=Category.MISCONFIG, url="https://example.com/a"),
            _finding(category=Category.MISCONFIG, url="https://example.com/b"),
            _finding(category=Category.MISCONFIG, url="https://example.com/a"),
        ]
        result = dedup_findings(findings)
        assert [f.url for f in result] == ["https://example.com/a", "https://example.com/b"]

    def test_input_list_is_not_mutated(self) -> None:
        findings = [_finding(tool="a"), _finding(tool="b")]
        original = list(findings)
        dedup_findings(findings)
        assert findings == original

    def test_empty_input(self) -> None:
        assert dedup_findings([]) == []
