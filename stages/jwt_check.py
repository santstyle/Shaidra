"""JWT discovery and active checks driven by jwt_tool.

Each in-scope base URL is fetched with httpx (redirects followed); the
Authorization header and Set-Cookie values are scanned for JWT-shaped strings
(three base64url segments whose header segment decodes to JSON carrying an
"alg" field). Every discovered token is then run through jwt_tool's active
test suite (``-M at``) against the endpoint that served it. A forged token is
counted as accepted when the endpoint answers it exactly like the original
valid token while a request without a token is answered differently. alg:none
and key-confusion acceptance is HIGH, other accepted forgeries are MEDIUM.
A weak-secret dictionary pass runs only when wordlists/jwt_secrets.txt exists
locally; no tokens or a missing jwt_tool degrades to a stage skip.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, JsonValue, ScanContext, Severity
from shaidra.utils.http import make_http_client
from shaidra.utils.process import RunOptions, run_tool
from shaidra.utils.rate_limiter import RateLimiter

STAGE: Final[str] = "JWT"
TOOL: Final[str] = "jwt_tool"
MAX_HOSTS: Final[int] = 20
MAX_TOKENS: Final[int] = 8
FETCH_TIMEOUT: Final[float] = 10.0
CRACK_TIMEOUT: Final[float] = 60.0
_ORIG_MOD: Final[str] = "Prescan: original token"
_NULL_MOD: Final[str] = "Prescan: no token"
_ANSI_RE: Final[re.Pattern[str]] = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_JWT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<header>[A-Za-z0-9_-]{8,})\.(?P<payload>[A-Za-z0-9_-]{8,})\.(?P<signature>[A-Za-z0-9_-]{8,})"
)
_RESPONSE_RE: Final[re.Pattern[str]] = re.compile(
    r"^jwttool_[0-9a-f]+\s+(?P<mod>.+?)\s+Response Code:\s+(?P<code>\d+),"
)


class _ForgeKind(StrEnum):
    """A forgery test jwt_tool runs during the -M at active suite."""

    ALG_NONE = "alg:none"
    KEY_CONFUSION = "key confusion"
    NULL_SIG = "null signature"
    BLANK_PW = "blank password"
    PSYCHIC = "psychic signature"
    KID = "kid injection"
    JWKS = "jwks injection"
    WEAK_SECRET = "weak hmac secret"


_FORGE_MARKERS: Final[tuple[tuple[str, _ForgeKind], ...]] = (
    ('"alg":"none"', _ForgeKind.ALG_NONE),
    ("key confusion", _ForgeKind.KEY_CONFUSION),
    ("null signature", _ForgeKind.NULL_SIG),
    ("blank password", _ForgeKind.BLANK_PW),
    ("psychic signature", _ForgeKind.PSYCHIC),
    ("injected kid claim", _ForgeKind.KID),
    ("jwks", _ForgeKind.JWKS),
    ("alternative accepted hmac signatures", _ForgeKind.WEAK_SECRET),
)


@dataclass(frozen=True, slots=True)
class _JwtHit:
    """A discovered token plus the transport jwt_tool needs to replay it."""

    token: str
    url: str
    host: str
    flag: str
    value: str


@dataclass(frozen=True, slots=True)
class _ForgeLine:
    """One accepted forgery test parsed from jwt_tool output."""

    kind: _ForgeKind
    mod: str


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Discover JWTs on live hosts, then run jwt_tool's active tests."""
    if not ctx.has_tool(TOOL):
        await bus.stage_skip(STAGE, "jwt_tool not installed")
        return
    await bus.stage_start(STAGE)
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    hits = await _discover(ctx, bus, limiter)
    if not hits:
        await bus.stage_skip(STAGE, "no JWTs discovered in response headers")
        return
    findings = await _check_tokens(ctx, bus, hits)
    await bus.stage_done(STAGE, f"{len(hits)} token(s) checked, {findings} forgery finding(s)")


async def _discover(ctx: ScanContext, bus: EventBus, limiter: RateLimiter) -> list[_JwtHit]:
    """Fetch every in-scope base URL and collect JWT-shaped header values."""
    bases = _in_scope_bases(ctx)
    hits: list[_JwtHit] = []
    async with make_http_client(ctx, follow_redirects=True, timeout=FETCH_TIMEOUT) as client:
        for base in bases:
            await limiter.acquire()
            try:
                response = await client.get(base)
            except (httpx.HTTPError, TimeoutError):
                continue
            _collect_hits(base, response.headers, hits)
            if len(hits) >= MAX_TOKENS:
                break
    return hits[:MAX_TOKENS]


def _in_scope_bases(ctx: ScanContext) -> list[str]:
    """Return up to MAX_HOSTS deduplicated in-scope base URLs."""
    bases: list[str] = []
    if ctx.target_url and ctx.scope.in_scope(ctx.target_url):
        bases.append(ctx.target_url.rstrip("/"))
    for host in ctx.live_hosts():
        if len(bases) >= MAX_HOSTS:
            break
        if host.url is None or not ctx.scope.in_scope(host.host):
            continue
        base = host.url.rstrip("/")
        if base not in bases:
            bases.append(base)
    return bases[:MAX_HOSTS]


def _collect_hits(base: str, headers: httpx.Headers, hits: list[_JwtHit]) -> None:
    """Append JWTs found in the Authorization and Set-Cookie response headers."""
    seen = {hit.token for hit in hits}
    authorization = headers.get("authorization")
    if authorization:
        token = _extract_jwt(authorization)
        if token is not None and token not in seen:
            hits.append(_JwtHit(token, base, _host_of(base), "-rh", f"Authorization: {authorization}"))
            seen.add(token)
    for cookie in headers.get_list("set-cookie"):
        token = _extract_jwt(cookie)
        if token is None or token in seen:
            continue
        name, _, _ = cookie.partition("=")
        name = name.strip()
        if not name:
            continue
        hits.append(_JwtHit(token, base, _host_of(base), "-rc", f"{name}={token}"))
        seen.add(token)


def _extract_jwt(text: str) -> str | None:
    """Return the first JWT-shaped match whose header decodes to JSON with alg."""
    for match in _JWT_RE.finditer(text):
        header = _b64_json(match.group("header"))
        if header is not None and isinstance(header.get("alg"), str):
            return match.group(0)
    return None


def _b64_json(segment: str) -> dict[str, JsonValue] | None:
    """Decode a base64url segment into a JSON object, or None when malformed."""
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
        decoded: JsonValue = json.loads(raw)
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if isinstance(decoded, dict):
        return decoded
    return None


async def _check_tokens(ctx: ScanContext, bus: EventBus, hits: list[_JwtHit]) -> int:
    """Run jwt_tool against every token; emit one finding per vulnerable token."""
    secrets = _local_secrets()
    timeout = float(ctx.config.timeout_for(TOOL))
    findings = 0
    await bus.stage_progress(STAGE, 0, len(hits))
    for index, hit in enumerate(hits, start=1):
        argv = [TOOL, hit.token, "-M", "at", "-t", hit.url, hit.flag, hit.value]
        result = await run_tool(argv, RunOptions(timeout=timeout, input_text="Y\n"))
        accepted = _accepted_forges(result.stdout)
        if accepted:
            findings += 1
            await bus.finding(_forgery_finding(hit, accepted))
        elif secrets is not None:
            crack = await run_tool([TOOL, hit.token, "-C", "-d", str(secrets)], RunOptions(timeout=CRACK_TIMEOUT))
            if _cracked(crack.stdout):
                findings += 1
                await bus.finding(_crack_finding(hit))
        await bus.stage_progress(STAGE, index, len(hits))
    return findings


def _local_secrets() -> Path | None:
    """Return the packaged weak-secret list when one exists locally, else None."""
    path = Path(__file__).resolve().parents[1] / "wordlists" / "jwt_secrets.txt"
    return path if path.is_file() else None


def _cracked(stdout: str) -> bool:
    """Recognise jwt_tool's dictionary-attack success markers."""
    cleaned = _ANSI_RE.sub("", stdout)
    return "CORRECT key found" in cleaned or "is the CORRECT key" in cleaned


def _accepted_forges(stdout: str) -> list[_ForgeLine]:
    """Return forgery tests the endpoint answered exactly like the real token."""
    probed: list[tuple[str, int]] = []
    for raw_line in stdout.splitlines():
        match = _RESPONSE_RE.match(_ANSI_RE.sub("", raw_line).strip())
        if match is not None:
            probed.append((match.group("mod"), int(match.group("code"))))
    codes = dict(probed)
    original = codes.get(_ORIG_MOD)
    missing = codes.get(_NULL_MOD)
    if original is None or missing is None or original == missing:
        return []
    accepted: list[_ForgeLine] = []
    seen: set[_ForgeKind] = set()
    for mod, code in probed:
        if code != original:
            continue
        kind = _classify(mod)
        if kind is None or kind in seen:
            continue
        seen.add(kind)
        accepted.append(_ForgeLine(kind=kind, mod=mod))
    return accepted


def _classify(mod: str) -> _ForgeKind | None:
    """Map a jwt_tool test label to its forgery kind, or None for non-forge lines."""
    text = mod.casefold()
    for needle, kind in _FORGE_MARKERS:
        if needle in text:
            return kind
    return None


def _severity_for(kinds: list[_ForgeKind]) -> Severity:
    """HIGH for alg-none/key confusion acceptances, MEDIUM for the rest."""
    for kind in kinds:
        match kind:
            case _ForgeKind.ALG_NONE | _ForgeKind.KEY_CONFUSION:
                return Severity.HIGH
            case _:
                continue
    return Severity.MEDIUM


def _forgery_finding(hit: _JwtHit, accepted: list[_ForgeLine]) -> Finding:
    """Assemble the finding for a token whose forged variants were accepted."""
    labels = ", ".join(sorted(line.kind.value for line in accepted))
    return Finding(
        title=f"JWT forgery accepted: {labels}",
        severity=_severity_for([line.kind for line in accepted]),
        category=Category.JWT,
        host=hit.host,
        tool=TOOL,
        url=hit.url,
        evidence=f"{hit.url} accepted forged token ({labels})",
        description=(
            f"The endpoint {hit.url} answered forged tokens with the same response as the "
            "original valid token while a request without a token was answered differently, "
            f"so the server accepts tokens forged via {labels}."
        ),
        raw={"url": hit.url, "accepted": [line.mod for line in accepted]},
    )


def _crack_finding(hit: _JwtHit) -> Finding:
    """Assemble the finding for a token cracked with the local weak-secret list."""
    return Finding(
        title="JWT signed with a weak secret",
        severity=Severity.MEDIUM,
        category=Category.JWT,
        host=hit.host,
        tool=TOOL,
        url=hit.url,
        evidence=f"{hit.url} (secret value redacted)",
        description=(
            "jwt_tool's dictionary attack reproduced this token's HMAC signature with a "
            "secret from the local weak-secret wordlist, so the signing key is guessable."
        ),
        raw={"url": hit.url},
    )


def _host_of(url: str) -> str:
    return urlsplit(url).hostname or url
