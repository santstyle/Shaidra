"""CMS fingerprinting and targeted CMS checks.

Each live in-scope base URL is fetched once and fingerprinted from its response
headers and body: WordPress (wp-content / wp-includes / wp-json), Drupal and
Joomla signatures, and any generator meta tag. A positive hit raises an
informational "CMS detected" finding and unlocks that CMS's targeted checks:

* WordPress - ``/wp-json/wp/v2/users`` for user enumeration, ``/readme.html``
  for version disclosure, and ``/xmlrpc.php`` for the legacy RPC endpoint.
* Drupal     - ``/CHANGELOG.txt`` for version disclosure.
* Joomla     - ``/administrator/`` login panel reachability.

When wpscan is installed and WordPress is detected, its JSON scan is merged in
so known core, plugin, and theme vulnerabilities are reported. Every request is
a GET throttled through RateLimiter; nothing is written to the target.
"""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Final
from urllib.parse import urlsplit

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, JsonValue, LogLevel, ScanContext, Severity
from shaidra.utils.process import RunOptions, run_tool
from shaidra.utils.rate_limiter import RateLimiter

STAGE: Final[str] = "CMS scan"
MAX_HOSTS: Final[int] = 30
TIMEOUT_SECONDS: Final[float] = 10.0
BODY_SNIFF: Final[int] = 8192
_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"version\s+([0-9][0-9A-Za-z._-]*)", re.IGNORECASE)


class Cms(StrEnum):
    """CMS families Shaidra fingerprints."""

    WORDPRESS = "WordPress"
    DRUPAL = "Drupal"
    JOOMLA = "Joomla"


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Fingerprint each target, run its CMS checks, and merge wpscan results."""
    await bus.stage_start(STAGE)
    targets = _targets(ctx)
    if not targets:
        await bus.stage_skip(STAGE, "no live in-scope hosts")
        return
    limiter = RateLimiter(float(max(1, ctx.rate_limit)))
    detected = 0
    wpscan_ready = ctx.has_tool("wpscan")
    async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT_SECONDS) as client:
        for base in targets:
            families = await _fingerprint(client, limiter, base)
            if not families:
                continue
            detected += 1
            await bus.finding(_detected_finding(base, families))
            if Cms.WORDPRESS in families:
                await _wordpress_checks(ctx, bus, client, limiter, base)
                if wpscan_ready:
                    await _wpscan(ctx, bus, base)
            if Cms.DRUPAL in families:
                await _drupal_checks(bus, client, limiter, base)
            if Cms.JOOMLA in families:
                await _joomla_checks(bus, client, limiter, base)
    await bus.stage_done(STAGE, f"{detected} CMS host(s)")


def _targets(ctx: ScanContext) -> list[str]:
    """Return deduplicated in-scope base URLs, capped at MAX_HOSTS."""
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


async def _fingerprint(client: httpx.AsyncClient, limiter: RateLimiter, base: str) -> set[Cms]:
    """Fetch the base URL and return the CMS families it matches."""
    await limiter.acquire()
    try:
        response = await client.get(base)
    except (httpx.HTTPError, TimeoutError):
        return set()
    body = response.text[:BODY_SNIFF].lower()
    generator = response.headers.get("x-generator", "").lower()
    powered = response.headers.get("x-powered-by", "").lower()
    return _classify(body, generator, powered)


def _classify(body: str, generator: str, powered: str) -> set[Cms]:
    """Map response signals to the CMS families they indicate."""
    families: set[Cms] = set()
    haystack = f"{body} {generator} {powered}"
    if "wp-content" in haystack or "wp-includes" in haystack or "/wp-json" in haystack or "wordpress" in generator:
        families.add(Cms.WORDPRESS)
    if "sites/default/files" in haystack or "drupal" in generator or "drupal" in powered:
        families.add(Cms.DRUPAL)
    if "option=com_" in haystack or "/media/jui/" in haystack or "joomla" in generator:
        families.add(Cms.JOOMLA)
    return families


async def _wordpress_checks(
    ctx: ScanContext, bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, base: str
) -> None:
    """Run the WordPress-specific disclosure checks."""
    users = await _get(client, limiter, f"{base}/wp-json/wp/v2/users")
    if users is not None and users.status_code == 200:
        slugs = _user_slugs(users.text)
        if slugs:
            await bus.finding(
                Finding(
                    title="WordPress user enumeration via REST API",
                    severity=Severity.MEDIUM,
                    category=Category.CMS,
                    host=_host_of(base),
                    tool="shaidra",
                    url=f"{base}/wp-json/wp/v2/users",
                    evidence=f"users exposed: {', '.join(slugs[:5])}",
                    description=(
                        "The WordPress REST users endpoint lists account slugs without "
                        "authentication, easing credential-stuffing and login attacks."
                    ),
                    raw={"users": slugs},
                )
            )

    readme = await _get(client, limiter, f"{base}/readme.html")
    if readme is not None and readme.status_code == 200 and "wordpress" in readme.text.lower():
        version = _first_version(readme.text)
        await bus.finding(
            Finding(
                title="WordPress version disclosure (readme.html)",
                severity=Severity.LOW,
                category=Category.CMS,
                host=_host_of(base),
                tool="shaidra",
                url=f"{base}/readme.html",
                evidence=f"readme.html exposed{f', version {version}' if version else ''}",
                description=(
                    "The WordPress readme.html file is publicly readable and may disclose the "
                    "core version, helping an attacker map known vulnerabilities."
                ),
                raw={"version": version},
            )
        )

    xmlrpc = await _get(client, limiter, f"{base}/xmlrpc.php")
    if xmlrpc is not None and xmlrpc.status_code == 200 and "xml-rpc server accepts post requests" in xmlrpc.text.lower():
        await bus.finding(
            Finding(
                title="WordPress XML-RPC endpoint enabled",
                severity=Severity.LOW,
                category=Category.CMS,
                host=_host_of(base),
                tool="shaidra",
                url=f"{base}/xmlrpc.php",
                evidence="xmlrpc.php accepts POST requests",
                description=(
                    "The legacy XML-RPC endpoint is enabled; it can be abused for "
                    "brute-force amplification and pingback reflection."
                ),
            )
        )


async def _drupal_checks(bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, base: str) -> None:
    """Check Drupal for the version-disclosing CHANGELOG.txt."""
    response = await _get(client, limiter, f"{base}/CHANGELOG.txt")
    if response is None or response.status_code != 200 or "drupal" not in response.text.lower():
        return
    version = _first_version(response.text)
    await bus.finding(
        Finding(
            title="Drupal version disclosure (CHANGELOG.txt)",
            severity=Severity.LOW,
            category=Category.CMS,
            host=_host_of(base),
            tool="shaidra",
            url=f"{base}/CHANGELOG.txt",
            evidence=f"CHANGELOG.txt exposed{f', version {version}' if version else ''}",
            description=(
                "The Drupal CHANGELOG.txt file is publicly readable and may disclose the core "
                "version, helping an attacker map known vulnerabilities."
            ),
            raw={"version": version},
        )
    )


async def _joomla_checks(bus: EventBus, client: httpx.AsyncClient, limiter: RateLimiter, base: str) -> None:
    """Check whether the Joomla administrator panel is reachable."""
    response = await _get(client, limiter, f"{base}/administrator/")
    if response is None or response.status_code != 200 or "joomla" not in response.text.lower():
        return
    await bus.finding(
        Finding(
            title="Joomla administrator panel exposed",
            severity=Severity.LOW,
            category=Category.CMS,
            host=_host_of(base),
            tool="shaidra",
            url=f"{base}/administrator/",
            evidence="administrator login panel reachable",
            description=(
                "The Joomla administrator login panel is reachable; if credentials are weak it "
                "is directly attackable and it should not be exposed publicly."
            ),
        )
    )


async def _wpscan(ctx: ScanContext, bus: EventBus, base: str) -> None:
    """Run wpscan against a detected WordPress host and merge its findings."""
    argv = [
        "wpscan",
        "--url",
        base,
        "--format",
        "json",
        "--no-banner",
        "--disable-tls-checks",
        "--random-user-agent",
    ]
    result = await run_tool(argv, RunOptions(timeout=float(ctx.config.timeout_for("wpscan"))))
    payload = _load_object(result.stdout)
    if payload is None:
        await bus.log("wpscan: no parsable JSON output", LogLevel.WARN)
        return
    findings = _wpscan_findings(payload, base)
    for finding in findings:
        await bus.finding(finding)
    await bus.log(f"wpscan: {len(findings)} vulnerability finding(s)")


def _wpscan_findings(payload: dict[str, JsonValue], base: str) -> list[Finding]:
    """Flatten wpscan's version/plugin/theme vulnerabilities into findings."""
    findings: list[Finding] = []
    version = payload.get("version")
    if isinstance(version, dict):
        if _text(version.get("status")) in {"insecure", "outdated"}:
            findings.append(_cms_vuln("WordPress core out of date", base, "wpscan", _text(version.get("number")), version))
        findings.extend(_wpscan_entry_vulns("WordPress core", version, base))
    findings.extend(_wpscan_component_vulns(payload.get("plugins"), "plugin", base))
    findings.extend(_wpscan_component_vulns(payload.get("themes"), "theme", base))
    main_theme = payload.get("main_theme")
    if isinstance(main_theme, dict):
        findings.extend(_wpscan_component_vulns({"main_theme": main_theme}, "theme", base))
    return findings


def _wpscan_component_vulns(components: JsonValue, kind: str, base: str) -> list[Finding]:
    """Collect vulnerability findings from a wpscan plugins/themes mapping."""
    if not isinstance(components, dict):
        return []
    findings: list[Finding] = []
    for slug, entry in components.items():
        if not isinstance(entry, dict):
            continue
        findings.extend(_wpscan_entry_vulns(f"{kind} {slug}", entry, base))
    return findings


def _wpscan_entry_vulns(label: str, entry: dict[str, JsonValue], base: str) -> list[Finding]:
    """Build one finding per vulnerability listed on a wpscan component."""
    vulnerabilities = entry.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return []
    version = _text(entry.get("version"))
    findings: list[Finding] = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        title = _text(item.get("title")) or "Known vulnerability"
        cves = item.get("references")
        cve = _first_cve(cves)
        findings.append(_cms_vuln(f"{label}: {title}", base, "wpscan", version, item, cve))
    return findings


def _cms_vuln(
    title: str,
    base: str,
    tool: str,
    version: str,
    raw: dict[str, JsonValue],
    cve: str | None = None,
) -> Finding:
    """Assemble a CMS vulnerability finding from a wpscan entry."""
    suffix = f" (version {version})" if version else ""
    return Finding(
        title=title,
        severity=Severity.HIGH if cve else Severity.MEDIUM,
        category=Category.CMS,
        host=_host_of(base),
        tool=tool,
        url=base,
        evidence=f"{title}{suffix}",
        description="wpscan reported this component as vulnerable.",
        cve=cve,
        raw=raw,
    )


async def _get(client: httpx.AsyncClient, limiter: RateLimiter, url: str) -> httpx.Response | None:
    """Rate-limited GET returning None on transport failure."""
    await limiter.acquire()
    try:
        return await client.get(url)
    except (httpx.HTTPError, TimeoutError):
        return None


def _detected_finding(base: str, families: set[Cms]) -> Finding:
    """Build the informational finding announcing the detected CMS."""
    names = ", ".join(sorted(family.value for family in families))
    return Finding(
        title=f"CMS detected: {names}",
        severity=Severity.INFO,
        category=Category.CMS,
        host=_host_of(base),
        tool="shaidra",
        url=base,
        evidence=f"{base} fingerprints as {names}",
        description="The response fingerprint identifies the content management system in use.",
        raw={"cms": sorted(family.value for family in families)},
    )


def _user_slugs(body: str) -> list[str]:
    """Extract account slugs from a WordPress REST users response."""
    try:
        payload: JsonValue = json.loads(body)
    except json.JSONDecodeError:
        return []
    if not isinstance(payload, list):
        return []
    slugs = [entry.get("slug") for entry in payload if isinstance(entry, dict) and isinstance(entry.get("slug"), str)]
    return [slug for slug in slugs if slug]


def _first_version(text: str) -> str:
    """Return the first version-like token in a disclosure file."""
    match = _VERSION_RE.search(text)
    return match.group(1) if match else ""


def _first_cve(references: JsonValue | None) -> str | None:
    """Return the first CVE identifier from a wpscan references mapping."""
    if not isinstance(references, dict):
        return None
    cve = references.get("cve")
    if isinstance(cve, list):
        for entry in cve:
            if isinstance(entry, str) and entry:
                return entry
    if isinstance(cve, str) and cve:
        return cve
    return None


def _load_object(text: str) -> dict[str, JsonValue] | None:
    try:
        payload: JsonValue = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _text(value: JsonValue | None) -> str:
    return value if isinstance(value, str) else ""


def _host_of(url: str) -> str:
    return urlsplit(url).hostname or url
