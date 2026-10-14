"""Tests for JWT stage helpers: extraction, base64 decode, classification."""

from __future__ import annotations

import base64
import json

import httpx

from shaidra.core.models import Severity
from shaidra.stages import jwt_check
from shaidra.stages.jwt_check import _JwtHit


def _b64url(data: dict) -> str:
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_b64_json_decodes_object() -> None:
    encoded = _b64url({"alg": "HS256", "typ": "JWT"})
    assert jwt_check._b64_json(encoded) == {"alg": "HS256", "typ": "JWT"}


def test_b64_json_returns_none_for_invalid() -> None:
    assert jwt_check._b64_json("!!!not-base64!!!") is None
    assert jwt_check._b64_json("") is None
    # valid base64 but not an object
    non_object = base64.urlsafe_b64encode(b"[1,2,3]").decode().rstrip("=")
    assert jwt_check._b64_json(non_object) is None


def _valid_jwt() -> str:
    # _JWT_RE requires each segment ≥ 8 base64url chars; empty-payload segments are too short
    header = _b64url({"alg": "HS256", "typ": "JWT"})
    payload = _b64url({"sub": "user12345", "iss": "example"})
    signature = "c2lnbmF0dXJl"  # "signature" base64url-padded to ≥ 8
    return f"{header}.{payload}.{signature}"


def test_extract_jwt_returns_token() -> None:
    token = _valid_jwt()
    assert jwt_check._extract_jwt(f"Bearer {token}") == token


def test_extract_jwt_rejects_bad_header() -> None:
    header = _b64url({"typ": "JWT"})  # no alg
    payload = _b64url({"sub": "user12345"})
    token = f"{header}.{payload}.c2lnbmF0dXJl"
    assert jwt_check._extract_jwt(f"Bearer {token}") is None


def test_extract_jwt_returns_none_when_absent() -> None:
    assert jwt_check._extract_jwt("Bearer not-a-jwt") is None
    assert jwt_check._extract_jwt("") is None


def test_collect_hits_from_authorization_header() -> None:
    token = _valid_jwt()
    headers = httpx.Headers({"Authorization": f"Bearer {token}"})
    hits: list[_JwtHit] = []
    jwt_check._collect_hits("https://example.com", headers, hits)
    assert len(hits) == 1
    assert hits[0].token == token
    assert hits[0].host == "example.com"
    assert hits[0].flag == "-rh"


def test_collect_hits_deduplicates() -> None:
    token = _valid_jwt()
    headers = httpx.Headers({"Authorization": f"Bearer {token}"})
    hits: list[_JwtHit] = []
    jwt_check._collect_hits("https://a.example", headers, hits)
    jwt_check._collect_hits("https://b.example", headers, hits)
    assert len(hits) == 1


def test_collect_hits_from_set_cookie() -> None:
    token = _valid_jwt()
    headers = httpx.Headers({"set-cookie": f"session={token}; Path=/"})
    hits: list[_JwtHit] = []
    jwt_check._collect_hits("https://example.com", headers, hits)
    assert len(hits) == 1
    assert hits[0].flag == "-rc"
    assert "session=" in hits[0].value


def test_classify_maps_markers() -> None:
    # _FORGE_MARKERS use the quoted JSON form for alg:none
    assert jwt_check._classify('Testing "alg":"none"') is jwt_check._ForgeKind.ALG_NONE
    assert jwt_check._classify("key confusion attack") is jwt_check._ForgeKind.KEY_CONFUSION
    assert jwt_check._classify("null signature") is jwt_check._ForgeKind.NULL_SIG
    assert jwt_check._classify("blank password") is jwt_check._ForgeKind.BLANK_PW
    assert jwt_check._classify("random text") is None


def test_severity_for_forgery_kinds() -> None:
    assert jwt_check._severity_for([jwt_check._ForgeKind.ALG_NONE]) is Severity.HIGH
    assert jwt_check._severity_for([jwt_check._ForgeKind.KEY_CONFUSION]) is Severity.HIGH
    assert jwt_check._severity_for([jwt_check._ForgeKind.NULL_SIG]) is Severity.MEDIUM


def test_host_of_url() -> None:
    assert jwt_check._host_of("https://example.com/path") == "example.com"
    assert jwt_check._host_of("not-a-url") == "not-a-url"


def test_accepted_forges_parses_matching_codes() -> None:
    # Real jwt_tool format: jwttool_<hex> <mod> Response Code: <code>,
    stdout = (
        "jwttool_abc123 Prescan: original token Response Code: 200,\n"
        "jwttool_abc123 Prescan: no token Response Code: 401,\n"
        'jwttool_abc123 Testing "alg":"none" Response Code: 200,\n'
        "jwttool_abc123 key confusion Response Code: 401,\n"
    )
    accepted = jwt_check._accepted_forges(stdout)
    assert len(accepted) == 1
    assert accepted[0].kind is jwt_check._ForgeKind.ALG_NONE


def test_accepted_forges_empty_when_no_match() -> None:
    assert jwt_check._accepted_forges("nothing here") == []
