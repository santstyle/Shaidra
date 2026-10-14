"""Misconfiguration checks: directly exposed files plus optional tool sweeps.

Shaidra probes a fixed list of well-known exposure files with its own httpx
client (rate limited), then optionally runs nuclei and testssl. Probes are
bounded by request and finding caps; missing tools degrade silently.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Final
from urllib.parse import urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, Host, JsonValue, ScanContext, Severity
from shaidra.utils.http import make_http_client
from shaidra.utils.process import RunOptions, run_tool, stream_lines
from shaidra.utils.rate_limiter import RateLimiter

STAGE_NAME: Final[str] = "Misconfiguration"
_HTTP_TIMEOUT: Final[float] = 10.0
_MAX_HOSTS: Final[int] = 5
_MAX_PROBE_REQUESTS: Final[int] = 600
_MAX_FINDINGS: Final[int] = 80
_MAX_NUCLEI_FINDINGS: Final[int] = 30
_MAX_TLS_FINDINGS: Final[int] = 5
_BODY_CAP: Final[int] = 16384

_EXPOSURE_PATHS: Final[tuple[str, ...]] = (
    # Version control metadata (source-code disclosure)
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".git/logs/HEAD",
    ".git/packed-refs",
    ".git/COMMIT_EDITMSG",
    ".svn/entries",
    ".svn/wc.db",
    ".hg/requires",
    ".bzr/README",
    # Environment files (leaked credentials)
    ".env",
    ".env.local",
    ".env.dev",
    ".env.development",
    ".env.test",
    ".env.staging",
    ".env.production",
    ".env.prod",
    ".env.backup",
    ".env.bak",
    ".env.old",
    ".env.save",
    ".env.example",
    ".env.json",
    "env.json",
    "env.js",
    # Configuration files
    "config.json",
    "config.js",
    "config.php",
    "config.yml",
    "config.yaml",
    "settings.py",
    "application.properties",
    "appsettings.json",
    "local.settings.json",
    "web.config",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    # Credentials and private keys
    "credentials.json",
    "serviceAccountKey.json",
    "service-account.json",
    "gcloud.json",
    ".aws/credentials",
    ".aws/config",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".ssh/authorized_keys",
    ".npmrc",
    ".dockercfg",
    ".docker/config.json",
    ".ftpconfig",
    ".remote-sync.json",
    "terraform.tfstate",
    "terraform.tfstate.backup",
    # WordPress
    "wp-config.php",
    "wp-config.php.bak",
    "wp-config.php~",
    "wp-config.php.save",
    "wp-config.php.old",
    "wp-config.txt",
    "wp-content/debug.log",
    # Backups and database dumps
    "backup.zip",
    "backup.tar.gz",
    "backup.tar",
    "backup.rar",
    "backup.7z",
    "site.zip",
    "www.zip",
    "web.zip",
    "backup.sql",
    "database.sql",
    "dump.sql",
    "data.sql",
    # Diagnostic and server files
    "phpinfo.php",
    "info.php",
    ".htaccess",
    ".htpasswd",
    ".DS_Store",
    "Thumbs.db",
    "server-status",
    "server-info",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    # Framework debug endpoints and API descriptions
    "actuator/env",
    "actuator/health",
    "actuator/httptrace",
    "swagger.json",
    "openapi.json",
    # Dependency locks (version fingerprinting)
    "package-lock.json",
    "composer.lock",
    "yarn.lock",
    "Gemfile.lock",
)
_HIGH_EXPOSURES: Final[frozenset[str]] = frozenset(
    {
        ".git/config",
        ".git/HEAD",
        ".git/index",
        ".git/logs/HEAD",
        ".git/packed-refs",
        ".env",
        ".env.local",
        ".env.dev",
        ".env.development",
        ".env.test",
        ".env.staging",
        ".env.production",
        ".env.prod",
        ".env.backup",
        ".env.bak",
        ".env.old",
        ".env.save",
        ".env.json",
        "env.json",
        "wp-config.php",
        "wp-config.php.bak",
        "wp-config.php~",
        "wp-config.php.save",
        "wp-config.php.old",
        "wp-config.txt",
        "credentials.json",
        "serviceAccountKey.json",
        "service-account.json",
        "gcloud.json",
        ".aws/credentials",
        ".aws/config",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".npmrc",
        ".dockercfg",
        ".docker/config.json",
        "terraform.tfstate",
        "terraform.tfstate.backup",
        "backup.sql",
        "database.sql",
        "dump.sql",
        "data.sql",
        "backup.zip",
        "backup.tar.gz",
        "backup.rar",
        "backup.7z",
        "site.zip",
        "www.zip",
        "web.zip",
    }
)
_LOW_EXPOSURES: Final[frozenset[str]] = frozenset(
    {
        ".env.example",
        ".DS_Store",
        "Thumbs.db",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
        "Dockerfile",
        "package-lock.json",
        "composer.lock",
        "yarn.lock",
        "Gemfile.lock",
    }
)
_KNOWN_EXPOSURES_NORM: Final[frozenset[str]] = frozenset(path.strip("/").lower() for path in _EXPOSURE_PATHS)


def is_known_exposure(path: str) -> bool:
    """Return whether a path is already covered by the verified exposure probe.

    Content discovery uses this to avoid re-reporting the same file the
    misconfig stage confirms with a content signature: the path-only
    classifier here would otherwise raise a duplicate, weaker finding.
    """
    return path.strip("/").lower() in _KNOWN_EXPOSURES_NORM


_HTACCESS_MARKERS: Final[tuple[str, ...]] = (
    "RewriteRule",
    "RewriteEngine",
    "Require ",
    "Order allow",
    "Deny from",
)
_ENV_LINE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", re.MULTILINE)
_HTPASSWD_LINE: Final[re.Pattern[str]] = re.compile(r"^[^\s:#][^:\s]*:.*$", re.MULTILINE)
_ANSI: Final[re.Pattern[str]] = re.compile(r"\x1b\[[0-9;]*m")
_TLS_PROTOCOL: Final[re.Pattern[str]] = re.compile(r"\b(SSLv[23]|TLS 1\.[01])\b")
_GIT_SHA: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40} ")
_YAML_KV: Final[re.Pattern[str]] = re.compile(r"^\s*[\w.-]+\s*:", re.MULTILINE)
_ENV_PATHS: Final[frozenset[str]] = frozenset(
    {
        ".env",
        ".env.local",
        ".env.dev",
        ".env.development",
        ".env.test",
        ".env.staging",
        ".env.production",
        ".env.prod",
        ".env.backup",
        ".env.bak",
        ".env.old",
        ".env.save",
        ".env.example",
        ".env.json",
    }
)
_SQL_MARKERS: Final[tuple[str, ...]] = (
    "mysql dump",
    "postgresql database dump",
    "create table",
    "insert into",
    "-- mysql",
)
_ARCHIVE_MAGIC: Final[dict[str, bytes]] = {
    "backup.zip": b"PK\x03\x04",
    "site.zip": b"PK\x03\x04",
    "www.zip": b"PK\x03\x04",
    "web.zip": b"PK\x03\x04",
    "backup.tar.gz": b"\x1f\x8b",
    "backup.rar": b"Rar!\x1a\x07",
    "backup.7z": b"7z\xbc\xaf\x27\x1c",
}
_HTML_PREFIXES: Final[tuple[str, ...]] = ("<!doctype", "<html", "<head", "<body")


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Probe live hosts for exposed files, then run nuclei/testssl if present."""
    await bus.stage_start(STAGE_NAME)
    if not ctx.web_reachable:
        await bus.stage_skip(STAGE_NAME, "target not reachable")
        return
    bases = _in_scope_bases(ctx)
    if not bases:
        await bus.stage_skip(STAGE_NAME, "no live in-scope hosts to probe")
        return
    tools_available = ctx.has_tool("nuclei") or _testssl_bin(ctx) is not None
    found = await _probe_exposures(ctx, bus, bases)
    found += await _via_nuclei(ctx, bus, bases)
    found += await _via_testssl(ctx, bus, bases[0])
    if found == 0 and not tools_available:
        await bus.stage_skip(STAGE_NAME, "no exposure confirmed and nuclei/testssl not installed")
        return
    await bus.stage_done(STAGE_NAME, f"{found} misconfiguration findings")


def _in_scope_bases(ctx: ScanContext) -> list[str]:
    bases: list[str] = []
    for host in ctx.live_hosts():
        if not ctx.scope.in_scope(host.host):
            continue
        base = _base_url(host)
        if base not in bases:
            bases.append(base)
        if len(bases) >= _MAX_HOSTS:
            break
    if not bases and ctx.scope.in_scope(ctx.target_url):
        bases.append(ctx.target_url.rstrip("/"))
    return bases


def _base_url(host: Host) -> str:
    if host.url is not None:
        return host.url.rstrip("/")
    netloc = host.host if host.port in (None, 80, 443) else f"{host.host}:{host.port}"
    return f"{host.scheme or 'https'}://{netloc}"


async def _probe_exposures(ctx: ScanContext, bus: EventBus, bases: Sequence[str]) -> int:
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    total = len(bases) * len(_EXPOSURE_PATHS)
    requests = 0
    found = 0
    async with make_http_client(ctx, timeout=_HTTP_TIMEOUT, follow_redirects=False) as client:
        for base in bases:
            host = urlsplit(base).hostname or ctx.target
            for path in _EXPOSURE_PATHS:
                if requests >= _MAX_PROBE_REQUESTS or found >= _MAX_FINDINGS:
                    return found
                requests += 1
                await bus.stage_progress(STAGE_NAME, requests, total)
                await limiter.acquire()
                status, body, ctype = await _bounded_get(client, f"{base}/{path}")
                if not _confirmed(path, status, body, ctype):
                    continue
                found += 1
                await bus.finding(
                    Finding(
                        title=f"Exposed file: {path}",
                        severity=_severity_for_path(path),
                        category=Category.MISCONFIG,
                        host=host,
                        tool="shaidra",
                        evidence=f"HTTP {status}, {len(body)} bytes",
                        url=f"{base}/{path}",
                        description="A well-known sensitive file is reachable and its content matches the expected signature.",
                        raw={"status": status, "path": path},
                    )
                )
    return found


async def _bounded_get(client: httpx.AsyncClient, url: str) -> tuple[int, bytes, str]:
    try:
        async with client.stream("GET", url) as response:
            ctype = response.headers.get("content-type", "")
            buffer = bytearray()
            async for chunk in response.aiter_bytes():
                buffer.extend(chunk)
                if len(buffer) >= _BODY_CAP:
                    break
            return response.status_code, bytes(buffer), ctype
    except httpx.HTTPError:
        return 0, b"", ""


def _severity_for_path(path: str) -> Severity:
    if path in _HIGH_EXPOSURES:
        return Severity.HIGH
    if path in _LOW_EXPOSURES:
        return Severity.LOW
    return Severity.MEDIUM


def _confirmed(path: str, status: int, body: bytes, ctype: str) -> bool:
    if status != 200 or not body:
        return False
    text = body.decode("utf-8", "replace")
    low = text.lower()
    stripped = text.lstrip()
    is_html = "text/html" in ctype.lower() or stripped[:64].lower().startswith(_HTML_PREFIXES)

    # --- Version control metadata ---
    if path == ".git/config":
        return "[core]" in text
    if path == ".git/HEAD":
        return "ref: refs/" in text
    if path == ".git/index":
        return body[:4] == b"DIRC"
    if path == ".git/logs/HEAD":
        return _GIT_SHA.search(text) is not None
    if path == ".git/packed-refs":
        return "# pack-refs" in text or "refs/heads" in text
    if path == ".git/COMMIT_EDITMSG":
        return not is_html and 3 < len(stripped) < 4000
    if path == ".svn/entries":
        return stripped[:3] in ("12\n", "10\n", "9\n", "8\n")
    if path == ".svn/wc.db":
        return body[:16] == b"SQLite format 3\x00"
    if path == ".hg/requires":
        return "revlog" in low
    if path == ".bzr/README":
        return "bzr" in low

    # --- Environment files ---
    if path in _ENV_PATHS or path == "env.json":
        if is_html:
            return False
        if path.endswith(".json"):
            return stripped.startswith("{")
        return _ENV_LINE.search(text) is not None
    if path == "env.js":
        return not is_html and (
            "api_key" in low or "secret" in low or "token" in low or _ENV_LINE.search(text) is not None
        )

    # --- Configuration files ---
    if path in ("config.json", "appsettings.json", "local.settings.json"):
        return not is_html and stripped.startswith("{") and stripped.rstrip().endswith("}")
    if path in ("config.yml", "config.yaml", "docker-compose.yml", "docker-compose.yaml"):
        return not is_html and _YAML_KV.search(text) is not None
    if path == "config.php":
        return "<?php" in text
    if path == "config.js":
        return not is_html and ("module.exports" in text or "export " in text)
    if path == "settings.py":
        return not is_html and any(k in text.upper() for k in ("SECRET", "DATABASE", "PASSWORD"))
    if path == "application.properties":
        return not is_html and _ENV_LINE.search(text) is not None
    if path == "web.config":
        return "<configuration" in low
    if path == "Dockerfile":
        return stripped.upper().startswith("FROM ")

    # --- Credentials and private keys ---
    if path == "credentials.json":
        return (
            not is_html
            and stripped.startswith("{")
            and any(k in low for k in ('"key"', "private_key", "client_email", "secret", "password"))
        )
    if path in ("serviceAccountKey.json", "service-account.json", "gcloud.json"):
        return not is_html and ("service_account" in low or "private_key" in low)
    if path in (".aws/credentials", ".aws/config"):
        return not is_html and ("aws_access_key_id" in low or "[default]" in low)
    if path in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".ssh/id_rsa", ".ssh/id_ed25519"):
        return "private key" in low
    if path == ".ssh/authorized_keys":
        return "ssh-rsa" in low or "ssh-ed25519" in low
    if path == ".npmrc":
        return "_authtoken" in low or "registry" in low
    if path in (".dockercfg", ".docker/config.json"):
        return not is_html and "auths" in low
    if path in (".ftpconfig", ".remote-sync.json"):
        return not is_html and '"host"' in low
    if path in ("terraform.tfstate", "terraform.tfstate.backup"):
        return not is_html and ("terraform" in low or '"resources"' in low or '"serial"' in low)

    # --- WordPress ---
    if path == "wp-content/debug.log":
        return not is_html and "php" in low and ("error" in low or "warning" in low or "notice" in low)
    if path.startswith("wp-config"):
        return "db_name" in low or "db_password" in low or "define(" in text

    # --- Backups and database dumps ---
    if path in _ARCHIVE_MAGIC:
        return body.startswith(_ARCHIVE_MAGIC[path])
    if path == "backup.tar":
        return len(body) > 262 and body[257:262] in (b"ustar", b"ustar\x00")
    if path.endswith(".sql"):
        return any(marker in low for marker in _SQL_MARKERS)

    # --- Diagnostic and server files ---
    if path in ("phpinfo.php", "info.php"):
        return "phpinfo" in low
    if path == ".htaccess":
        return any(marker in text for marker in _HTACCESS_MARKERS)
    if path == ".htpasswd":
        return _HTPASSWD_LINE.search(text) is not None
    if path == ".DS_Store":
        return body[:4] == b"\x00\x00\x00\x01" or b"Bud1" in body[:32]
    if path == "Thumbs.db":
        return body[:4] == b"\xd0\xcf\x11\xe0"
    if path == "server-status":
        return "apache server status" in low
    if path == "server-info":
        return "apache server information" in low
    if path == "crossdomain.xml":
        return "cross-domain-policy" in low
    if path == "clientaccesspolicy.xml":
        return "access-policy" in low

    # --- Framework debug endpoints and API descriptions ---
    if path == "actuator/env":
        return not is_html and ("propertysources" in low or "activeprofiles" in low)
    if path == "actuator/health":
        return not is_html and '"status"' in low
    if path == "actuator/httptrace":
        return not is_html and '"traces"' in low
    if path in ("swagger.json", "openapi.json"):
        return not is_html and ('"swagger"' in low or '"openapi"' in low)

    # --- Dependency locks ---
    if path == "package-lock.json":
        return not is_html and '"lockfileversion"' in low
    if path == "composer.lock":
        return not is_html and '"packages"' in low
    if path == "yarn.lock":
        return "# yarn lockfile" in low
    if path == "Gemfile.lock":
        return low.lstrip().startswith("gem ") or "\ngem " in low
    return False


async def _via_nuclei(ctx: ScanContext, bus: EventBus, bases: Sequence[str]) -> int:
    if not ctx.has_tool("nuclei"):
        return 0
    argv = [
        "nuclei",
        "-silent",
        "-nc",
        "-jsonl",
        "-tags",
        "exposure,misconfig",
        "-rate-limit",
        str(max(1, ctx.rate_limit)),
        "-u",
        ",".join(bases),
    ]
    options = RunOptions(timeout=ctx.config.timeout_for("nuclei"))
    found = 0
    async for line in stream_lines(argv, options):
        if found >= _MAX_NUCLEI_FINDINGS:
            break
        finding = _nuclei_finding(line, ctx)
        if finding is None:
            continue
        found += 1
        await bus.finding(finding)
    return found


def _nuclei_finding(line: str, ctx: ScanContext) -> Finding | None:
    try:
        payload: JsonValue = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    info = payload.get("info")
    if not isinstance(info, dict):
        return None
    name = info.get("name")
    if not isinstance(name, str) or not name:
        return None
    matched = payload.get("matched-at")
    matched_url = matched if isinstance(matched, str) else ""
    template = payload.get("template-id") or payload.get("templateID")
    raw_severity = info.get("severity")
    return Finding(
        title=name,
        severity=_severity(raw_severity if isinstance(raw_severity, str) else ""),
        category=Category.MISCONFIG,
        host=urlsplit(matched_url).hostname or ctx.target,
        tool="nuclei",
        evidence=line[:300],
        url=matched_url or None,
        description="The nuclei exposure/misconfig tag set matched this host.",
        template=template if isinstance(template, str) else None,
    )


def _severity(raw: str) -> Severity:
    match raw.lower():
        case "critical":
            return Severity.CRITICAL
        case "high":
            return Severity.HIGH
        case "medium":
            return Severity.MEDIUM
        case "low":
            return Severity.LOW
        case "info":
            return Severity.INFO
        case _:
            return Severity.UNKNOWN


def _testssl_bin(ctx: ScanContext) -> str | None:
    if ctx.has_tool("testssl.sh"):
        return "testssl.sh"
    if ctx.has_tool("testssl"):
        return "testssl"
    return None


async def _via_testssl(ctx: ScanContext, bus: EventBus, base: str) -> int:
    binary = _testssl_bin(ctx)
    if binary is None:
        return 0
    argv = [binary, "--quiet", "--warnings", "off", base]
    options = RunOptions(timeout=ctx.config.timeout_for("testssl"))
    result = await run_tool(argv, options)
    host = urlsplit(base).hostname or ctx.target
    found = 0
    for protocol, evidence in _weak_tls(result.stdout):
        if found >= _MAX_TLS_FINDINGS:
            break
        found += 1
        await bus.finding(
            Finding(
                title=f"Weak TLS protocol enabled: {protocol}",
                severity=Severity.MEDIUM,
                category=Category.MISCONFIG,
                host=host,
                tool=binary,
                evidence=evidence[:200],
                url=base,
                description="testssl reported a deprecated protocol or weak TLS configuration.",
            )
        )
    return found


def _weak_tls(stdout: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw in _ANSI.sub("", stdout).splitlines():
        line = raw.strip()
        protocol = _TLS_PROTOCOL.search(line)
        if protocol is None:
            continue
        lowered = line.lower()
        if "not offered" in lowered or "not supported" in lowered or "rejected" in lowered:
            continue
        if "offered" not in lowered and "vulnerable" not in lowered and "accepted" not in lowered:
            continue
        name = protocol.group(1)
        if name in seen:
            continue
        seen.add(name)
        hits.append((name, line))
    return hits
