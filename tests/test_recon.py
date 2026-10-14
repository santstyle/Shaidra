"""Tests for recon stage pure helpers: host parsing, title extraction, HTTPX line mapping."""

from __future__ import annotations

import json

from shaidra.core.config import Config
from shaidra.core.models import Category, Host, ScanContext
from shaidra.core.scope import Scope
from shaidra.stages import recon


def _ctx() -> ScanContext:
    return ScanContext(
        target="example.com",
        target_url="https://example.com",
        mode="quick",
        categories={Category.RECON},
        rate_limit=40,
        extended=False,
        scope=Scope(("example.com",)),
        config=Config(),
        verbose=False,
    )


def test_bare_host_strips_port_and_ipv6_brackets() -> None:
    assert recon._bare_host("example.com:8080") == "example.com"
    assert recon._bare_host("example.com") == "example.com"
    assert recon._bare_host("[2001:db8::1]:8443") == "2001:db8::1"
    assert recon._bare_host("[::1]") == "::1"


def test_bare_host_ignores_non_numeric_tail() -> None:
    assert recon._bare_host("example.com:https") == "example.com:https"


def test_is_bare_ip() -> None:
    assert recon._is_bare_ip("192.0.2.1") is True
    assert recon._is_bare_ip("::1") is True
    assert recon._is_bare_ip("example.com") is False


def test_parse_host_port_valid_and_invalid() -> None:
    assert recon._parse_host_port("example.com:443") == ("example.com", 443)
    assert recon._parse_host_port("  10.0.0.1:80  ") == ("10.0.0.1", 80)
    assert recon._parse_host_port("example.com") is None
    assert recon._parse_host_port("") is None
    assert recon._parse_host_port("a:b:c") is None
    assert recon._parse_host_port("host:abc") is None
    assert recon._parse_host_port(":443") is None


def test_extract_title_basic_and_unescape() -> None:
    assert recon._extract_title("<title>Home Page</title>") == "Home Page"
    assert recon._extract_title("<html><title>A &amp; B</title></html>") == "A & B"
    assert recon._extract_title('<TITLE class="x">Hi</TITLE>') == "Hi"


def test_extract_title_missing_empty_and_long() -> None:
    assert recon._extract_title("<html><body>no title</body></html>") is None
    assert recon._extract_title("<title></title>") is None
    long = "t" * 250
    assert recon._extract_title(f"<title>{long}</title>") == "t" * 200


def test_opt_str_and_opt_int() -> None:
    assert recon._opt_str("x") == "x"
    assert recon._opt_str("") is None
    assert recon._opt_str(1) is None
    assert recon._opt_int(5) == 5
    assert recon._opt_int(True) is None
    assert recon._opt_int("5") is None
    assert recon._opt_int(None) is None


def test_host_from_httpx_line_parses_record() -> None:
    record = {
        "url": "https://example.com",
        "host": "example.com",
        "ip": "192.0.2.1",
        "port": 443,
        "scheme": "https",
        "status_code": 200,
        "title": "Home",
        "webserver": "nginx",
        "content_length": 1234,
        "tech": ["nginx", 42],
        "cdn": True,
    }
    host = recon._host_from_httpx_line(json.dumps(record))
    assert host is not None
    assert host.host == "example.com"
    assert host.url == "https://example.com"
    assert host.ip == "192.0.2.1"
    assert host.port == 443
    assert host.status_code == 200
    assert host.title == "Home"
    assert host.server == "nginx"
    assert host.content_length == 1234
    assert host.tech == ["nginx"]
    assert host.cdn is True
    assert host.is_live is True
    assert host.source == "httpx"


def test_host_from_httpx_line_falls_back_to_url_hostname() -> None:
    record = {"url": "https://sub.example.com/path", "status_code": 200}
    host = recon._host_from_httpx_line(json.dumps(record))
    assert host is not None
    assert host.host == "sub.example.com"


def test_host_from_httpx_line_rejects_bad_input() -> None:
    assert recon._host_from_httpx_line("not json") is None
    assert recon._host_from_httpx_line("[]") is None
    assert recon._host_from_httpx_line('{"host": "x"}') is None
    assert recon._host_from_httpx_line('{"url": "https://"}') is None


def test_admin_ports_known_services() -> None:
    assert recon._ADMIN_PORTS[3306] == "MySQL"
    assert recon._ADMIN_PORTS[5432] == "PostgreSQL"
    assert recon._ADMIN_PORTS[6379] == "Redis"
    assert recon._ADMIN_PORTS[27017] == "MongoDB"


def test_match_host_by_key_and_ip() -> None:
    ctx = _ctx()
    host = Host(host="example.com", ip="192.0.2.1")
    ctx.add_host(host)
    assert recon._match_host(ctx, "example.com") is host
    assert recon._match_host(ctx, "192.0.2.1") is host
    assert recon._match_host(ctx, "other.com") is None


def test_load_subdomain_labels(tmp_path) -> None:
    wordlist = tmp_path / "subs.txt"
    wordlist.write_text("# comment\nwww\n\napi\n", encoding="utf-8")
    assert recon._load_subdomain_labels(str(wordlist)) == ["www", "api"]


def test_resolve_subdomain_wordlist(tmp_path) -> None:
    wordlist = tmp_path / "x.txt"
    wordlist.write_text("www\n", encoding="utf-8")
    assert recon._resolve_subdomain_wordlist(str(wordlist)) == wordlist
    assert recon._resolve_subdomain_wordlist("no-such-wordlist-xyz.txt") is None


def test_tool_timeout_uses_config_default() -> None:
    ctx = _ctx()
    assert recon._tool_timeout(ctx, "nuclei") == float(Config().timeout_for("nuclei"))
