"""Unit tests for the built-in version-to-CVE table."""

from __future__ import annotations

import pytest

from shaidra.core.models import Severity
from shaidra.utils.cve_db import match_tech, parse_tech


def test_parse_tech_extracts_name_and_version() -> None:
    assert parse_tech("Apache/2.4.49 (Ubuntu)") == ("apache", (2, 4, 49))
    assert parse_tech("nginx 1.24.0") == ("nginx", (1, 24, 0))
    assert parse_tech("Apache Tomcat/9.0.30") == ("apache tomcat", (9, 0, 30))


@pytest.mark.parametrize("token", ["Express", "nginx", "WordPress", "", "   "])
def test_parse_tech_rejects_tokens_without_version(token: str) -> None:
    assert parse_tech(token) is None


@pytest.mark.parametrize(
    ("token", "cve"),
    [
        ("Apache/2.4.49 (Ubuntu)", "CVE-2021-41773"),
        ("Apache/2.4.50 (Debian)", "CVE-2021-42013"),
        ("nginx/1.20.0", "CVE-2021-23017"),
        ("Apache Tomcat/9.0.30", "CVE-2020-1938"),
        ("jQuery/1.12.4", "CVE-2020-11022"),
        ("Drupal 7.56", "CVE-2018-7600"),
        ("WordPress 4.7.1", "CVE-2017-1001000"),
    ],
)
def test_match_tech_flags_vulnerable_versions(token: str, cve: str) -> None:
    assert cve in {entry.cve for entry in match_tech(token)}


@pytest.mark.parametrize(
    "token",
    [
        "Apache/2.4.58 (Ubuntu)",
        "nginx/1.24.0",
        "Apache Tomcat/9.0.31",
        "jQuery/3.6.0",
        "WordPress 4.7.2",
        "PHP/8.1.0",
        "Express",
    ],
)
def test_match_tech_ignores_patched_or_unknown(token: str) -> None:
    assert match_tech(token) == []


def test_apache_path_traversal_is_critical() -> None:
    (entry,) = match_tech("Apache/2.4.49")
    assert entry.severity is Severity.CRITICAL
    assert entry.cve == "CVE-2021-41773"
