"""Tests for the JSON / Markdown / plain-text report writers.

Reports are written only when -o is passed; findings must be ordered
most-severe-first in every format and non-JSON values must be coerced so
the JSON writer never raises mid-serialization.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shaidra.core.config import Config
from shaidra.core.models import Category, Finding, Host, ScanContext, Severity
from shaidra.core.scope import Scope
from shaidra.output.report import write_reports


def _ctx(findings: list[Finding] | None = None) -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.RECON, Category.WEBVULN},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        findings=findings or [],
        available_tools={"nuclei": True, "ffuf": False},
        waf=None,
    )


def _finding(severity: Severity, title: str = "Issue", **kwargs: object) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=Category.WEBVULN,
        host="example.com",
        tool="test",
        url="https://example.com/q",
        **kwargs,  # type: ignore[arg-type]
    )


class TestFormatSelection:
    def test_empty_formats_writes_nothing_and_skips_directory(self, tmp_path: Path) -> None:
        outdir = tmp_path / "reports"
        assert write_reports(_ctx(), set(), outdir, "run") == []
        assert not outdir.exists()

    def test_unknown_format_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unknown report format"):
            write_reports(_ctx(), {"json", "pdf"}, tmp_path, "run")

    def test_all_three_formats_written(self, tmp_path: Path) -> None:
        written = write_reports(_ctx(), {"json", "markdown", "txt"}, tmp_path, "run")
        assert [p.name for p in written] == ["run.json", "run.md", "run.txt"]
        assert all(p.is_file() for p in written)

    def test_missing_output_directory_is_created(self, tmp_path: Path) -> None:
        outdir = tmp_path / "nested" / "deep"
        write_reports(_ctx(), {"json"}, outdir, "run")
        assert (outdir / "run.json").is_file()


class TestJsonReport:
    def test_summary_counts_by_severity(self, tmp_path: Path) -> None:
        findings = [_finding(Severity.CRITICAL), _finding(Severity.CRITICAL), _finding(Severity.INFO)]
        path = write_reports(_ctx(findings), {"json"}, tmp_path, "run")[0]
        document = json.loads(path.read_text(encoding="utf-8"))
        assert document["summary"] == {
            "total": 3,
            "by_severity": {"critical": 2, "high": 0, "medium": 0, "low": 0, "info": 1, "unknown": 0},
        }

    def test_findings_ordered_most_severe_first(self, tmp_path: Path) -> None:
        findings = [
            _finding(Severity.INFO, "info-one"),
            _finding(Severity.CRITICAL, "crit"),
            _finding(Severity.LOW, "low"),
        ]
        path = write_reports(_ctx(findings), {"json"}, tmp_path, "run")[0]
        document = json.loads(path.read_text(encoding="utf-8"))
        titles = [item["title"] for item in document["findings"]]
        assert titles == ["crit", "low", "info-one"]

    def test_scan_metadata_and_targets_are_serialized(self, tmp_path: Path) -> None:
        ctx = _ctx()
        ctx.waf = "Cloudflare"
        ctx.hosts["example.com"] = Host(host="example.com", is_live=True, url="https://example.com")
        path = write_reports(ctx, {"json"}, tmp_path, "run")[0]
        document = json.loads(path.read_text(encoding="utf-8"))
        assert document["target"] == {"host": "example.com", "url": "https://example.com"}
        assert document["scan"]["waf"] == "Cloudflare"
        assert document["scan"]["rate_limit"] == 40
        assert document["scan"]["categories"] == ["recon", "webvuln"]
        assert document["scan"]["tools_available"] == {"ffuf": False, "nuclei": True}
        assert document["hosts"][0]["host"] == "example.com"

    def test_non_json_raw_values_are_stringified(self, tmp_path: Path) -> None:
        odd = _finding(Severity.HIGH)
        odd.raw = {"set": {1, 2}, "nested": {"tuple": (3, 4)}, "plain": "text"}
        path = write_reports(_ctx([odd]), {"json"}, tmp_path, "run")[0]
        document = json.loads(path.read_text(encoding="utf-8"))
        raw = document["findings"][0]["raw"]
        assert raw["plain"] == "text"
        assert isinstance(raw["set"], str)
        assert isinstance(raw["nested"]["tuple"], str)


class TestMarkdownReport:
    def test_contains_metadata_summary_and_findings(self, tmp_path: Path) -> None:
        findings = [_finding(Severity.CRITICAL, "RCE in endpoint")]
        path = write_reports(_ctx(findings), {"markdown"}, tmp_path, "run")[0]
        text = path.read_text(encoding="utf-8")
        assert text.startswith("# Shaidra Scan Report - example.com")
        assert "## Scan metadata" in text
        assert "| CRITICAL | 1 |" in text
        assert "### CRITICAL" in text
        assert "#### RCE in endpoint" in text
        assert "**Host:** example.com" in text

    def test_no_findings_message(self, tmp_path: Path) -> None:
        path = write_reports(_ctx(), {"markdown"}, tmp_path, "run")[0]
        assert "_No findings._" in path.read_text(encoding="utf-8")

    def test_waf_not_detected_shows_in_metadata(self, tmp_path: Path) -> None:
        path = write_reports(_ctx(), {"markdown"}, tmp_path, "run")[0]
        assert "**WAF:** not detected" in path.read_text(encoding="utf-8")


class TestTxtReport:
    def test_contains_header_summary_and_findings(self, tmp_path: Path) -> None:
        findings = [_finding(Severity.HIGH, "Open redirect")]
        path = write_reports(_ctx(findings), {"txt"}, tmp_path, "run")[0]
        text = path.read_text(encoding="utf-8")
        assert text.startswith("SHAIDRA SCAN REPORT - example.com")
        assert "SEVERITY SUMMARY" in text
        assert "HIGH" in text
        assert "Open redirect" in text
        assert "URL" in text  # optional field rendered

    def test_no_findings_message(self, tmp_path: Path) -> None:
        path = write_reports(_ctx(), {"txt"}, tmp_path, "run")[0]
        assert "No findings." in path.read_text(encoding="utf-8")

    def test_optional_fields_omitted_when_absent(self, tmp_path: Path) -> None:
        finding = _finding(Severity.INFO, "Bare")
        finding.url = None
        finding.description = ""
        finding.evidence = ""
        path = write_reports(_ctx([finding]), {"txt"}, tmp_path, "run")[0]
        text = path.read_text(encoding="utf-8")
        assert "Description" not in text
        assert "Evidence" not in text
