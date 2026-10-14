"""Tests for scope parsing and enforcement — the guardrail that keeps
out-of-scope hosts from being actively scanned.

Covers target parsing (URL / host:port / bare host / IPv6), scope-file
parsing (comments, wildcards, URLs, CIDRs), and `in_scope` matching rules.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shaidra.core.scope import (
    Scope,
    ScopeError,
    TargetSpec,
    build_scope,
    normalize_host,
    parse_target,
)


class TestParseTarget:
    def test_full_url_keeps_explicit_scheme(self) -> None:
        spec = parse_target("https://example.com/path?q=1")
        assert spec == TargetSpec(scheme="https", host="example.com", port=None)

    def test_bare_host_defaults_to_https(self) -> None:
        assert parse_target("example.com").scheme == "https"

    def test_well_known_http_port_defaults_to_http(self) -> None:
        for port in (80, 3000, 5000, 8000, 8080, 8888):
            spec = parse_target(f"example.com:{port}")
            assert spec.scheme == "http", port
            assert spec.port == port

    def test_non_http_port_defaults_to_https(self) -> None:
        spec = parse_target("example.com:8443")
        assert spec.scheme == "https"
        assert spec.port == 8443

    def test_explicit_scheme_wins_over_port_guess(self) -> None:
        spec = parse_target("http://example.com:8443")
        assert spec.scheme == "http"
        assert spec.port == 8443

    def test_host_is_lowercased_and_trailing_dot_stripped(self) -> None:
        assert parse_target("EXAMPLE.COM.").host == "example.com"

    def test_non_numeric_port_suffix_treated_as_hostname(self) -> None:
        spec = parse_target("example.com:notaport")
        assert spec.host == "example.com:notaport"
        assert spec.port is None

    def test_ipv6_host_without_port(self) -> None:
        spec = parse_target("[2001:db8::1]")
        assert spec.host == "[2001:db8::1]"
        assert spec.port is None

    def test_whitespace_is_trimmed(self) -> None:
        assert parse_target("  example.com  ").host == "example.com"

    def test_host_port_and_url_properties(self) -> None:
        assert TargetSpec(scheme="https", host="a.com", port=None).host_port == "a.com"
        assert TargetSpec(scheme="https", host="a.com", port=None).url == "https://a.com"
        assert TargetSpec(scheme="http", host="a.com", port=8080).host_port == "a.com:8080"
        assert TargetSpec(scheme="http", host="a.com", port=8080).url == "http://a.com:8080"


class TestNormalizeHost:
    def test_empty_and_whitespace(self) -> None:
        assert normalize_host("") == ""
        assert normalize_host("   ") == ""

    def test_url_reduces_to_hostname(self) -> None:
        assert normalize_host("https://Example.COM:8443/path") == "example.com"

    def test_host_port_strips_port(self) -> None:
        assert normalize_host("example.com:8080") == "example.com"

    def test_trailing_dot_and_case_folded(self) -> None:
        assert normalize_host("Example.COM.") == "example.com"

    def test_path_only_stripped_when_scheme_present(self) -> None:
        # Without a scheme any "/" is treated as CIDR-ish and left intact;
        # URLs with a scheme go through urlsplit and lose their path.
        assert normalize_host("example.com/admin/login") == "example.com/admin/login"
        assert normalize_host("https://example.com/admin/login") == "example.com"

    def test_cidr_is_preserved(self) -> None:
        assert normalize_host("192.168.0.0/16") == "192.168.0.0/16"

    def test_ipv6_is_preserved(self) -> None:
        assert normalize_host("[2001:DB8::1]") == "[2001:db8::1]"


class TestScopeFromfile:
    def test_parses_rules_and_skips_comments_and_blanks(self, tmp_path: Path) -> None:
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text(
            "# comment line\n"
            "\n"
            "; alternate comment\n"
            "example.com\n"
            "EXAMPLE.org.\n"
            "https://Sub.Example.net/path\n"
            "*.wild.example.com\n"
            "192.168.0.0/16\n",
            encoding="utf-8",
        )
        scope = Scope.from_file(scope_file)
        assert scope.rules == (
            "example.com",
            "example.org",
            "sub.example.net",
            "*.wild.example.com",
            "192.168.0.0/16",
        )

    def test_missing_file_raises_scope_error(self, tmp_path: Path) -> None:
        with pytest.raises(ScopeError, match="cannot read scope file"):
            Scope.from_file(tmp_path / "nope.txt")

    def test_file_without_usable_rules_raises(self, tmp_path: Path) -> None:
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("# only a comment\n\n; nothing else\n", encoding="utf-8")
        with pytest.raises(ScopeError, match="no usable rules"):
            Scope.from_file(scope_file)

    def test_wildcard_only_line_is_dropped(self, tmp_path: Path) -> None:
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("*.\nexample.com\n", encoding="utf-8")
        assert Scope.from_file(scope_file).rules == ("example.com",)


class TestInScope:
    def test_exact_domain_and_subdomains(self) -> None:
        scope = Scope(("example.com",))
        assert scope.in_scope("example.com") is True
        assert scope.in_scope("sub.example.com") is True
        assert scope.in_scope("deep.sub.example.com") is True

    def test_lookalike_hosts_are_rejected(self) -> None:
        scope = Scope(("example.com",))
        assert scope.in_scope("notexample.com") is False
        assert scope.in_scope("example.com.evil.net") is False
        assert scope.in_scope("example.org") is False

    def test_url_and_case_and_port_inputs_normalize(self) -> None:
        scope = Scope(("example.com",))
        assert scope.in_scope("https://EXAMPLE.com/login") is True
        assert scope.in_scope("example.com:8443") is True
        assert scope.in_scope("EXAMPLE.COM.") is True

    def test_empty_host_is_never_in_scope(self) -> None:
        assert Scope(("example.com",)).in_scope("") is False
        assert Scope(("example.com",)).in_scope("   ") is False

    def test_empty_scope_matches_nothing(self) -> None:
        scope = Scope.empty()
        assert scope.is_empty() is True
        assert scope.in_scope("example.com") is False

    def test_non_empty_scope_reports_rules(self) -> None:
        assert Scope(("example.com",)).is_empty() is False

    def test_wildcard_rule_matches_apex_and_subdomains(self) -> None:
        scope = Scope(("*.example.com",))
        assert scope.in_scope("example.com") is True
        assert scope.in_scope("a.example.com") is True
        assert scope.in_scope("other.com") is False

    def test_cidr_rule_matches_addresses_in_network(self) -> None:
        scope = Scope(("192.168.0.0/16",))
        assert scope.in_scope("192.168.1.5") is True
        assert scope.in_scope("https://192.168.255.1") is True
        assert scope.in_scope("10.0.0.1") is False

    def test_cidr_rule_rejects_non_ip_host(self) -> None:
        assert Scope(("10.0.0.0/8",)).in_scope("example.com") is False

    def test_bare_ip_rule(self) -> None:
        scope = Scope(("93.184.216.34",))
        assert scope.in_scope("93.184.216.34") is True
        assert scope.in_scope("93.184.216.35") is False


class TestBuildScope:
    def test_without_file_scopes_to_target(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        scope = build_scope("https://Example.com/path")
        assert scope.rules == ("example.com",)
        assert scope.in_scope("sub.example.com") is True

    def test_with_file_appends_target(self, tmp_path: Path) -> None:
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("other.org\n", encoding="utf-8")
        scope = build_scope("example.com", str(scope_file))
        assert scope.rules == ("other.org", "example.com")
        assert scope.in_scope("other.org") is True
        assert scope.in_scope("example.com") is True

    def test_with_file_missing_raises_scope_error(self, tmp_path: Path) -> None:
        with pytest.raises(ScopeError):
            build_scope("example.com", str(tmp_path / "absent.txt"))
