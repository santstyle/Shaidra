"""Curated version-to-CVE table for the built-in CVE fallback.

The built-in matcher runs when nuclei is unavailable. It only maps service
banner versions (from ``Server``, ``X-Powered-By`` and ``X-Generator`` headers,
plus WhatWeb plugin versions) onto a small set of well-known, unambiguous CVEs,
so it errs toward precision: every finding it raises is explicitly version-based
and must be verified against the exact build. nuclei (when installed) remains
the authoritative CVE source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from shaidra.core.models import Severity

# "apache/2.4.49", "nginx 1.24.0", "apache tomcat/9.0.30", "wordpress 5.8"
_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"^(?P<name>[a-z][a-z0-9._+ -]*?)[ /]v?(?P<ver>\d+(?:\.\d+){0,3})")


@dataclass(frozen=True, slots=True)
class CveEntry:
    """One product/version condition mapped to a single CVE."""

    product: str
    cve: str
    severity: Severity
    title: str
    summary: str
    min_inclusive: tuple[int, ...] | None = None
    max_exclusive: tuple[int, ...] | None = None
    exact: tuple[int, ...] | None = None


# Every bound below is a well-documented patch boundary. Where a product needs
# several disjoint vulnerable ranges, each range is its own entry.
_ENTRIES: Final[tuple[CveEntry, ...]] = (
    CveEntry(
        product="apache",
        cve="CVE-2021-41773",
        severity=Severity.CRITICAL,
        title="Apache HTTP Server 2.4.49 path traversal (CVE-2021-41773)",
        summary=(
            "Apache HTTP Server 2.4.49 has a path-traversal flaw that lets a request escape the "
            "document root; with mod_cgi enabled it can lead to remote code execution."
        ),
        exact=(2, 4, 49),
    ),
    CveEntry(
        product="apache",
        cve="CVE-2021-42013",
        severity=Severity.CRITICAL,
        title="Apache HTTP Server 2.4.50 path traversal (CVE-2021-42013)",
        summary=(
            "Apache HTTP Server 2.4.50 ships an incomplete fix for CVE-2021-41773, so path "
            "traversal (and possible remote code execution) still works."
        ),
        exact=(2, 4, 50),
    ),
    CveEntry(
        product="nginx",
        cve="CVE-2021-23017",
        severity=Severity.HIGH,
        title="nginx resolver off-by-one (CVE-2021-23017)",
        summary=(
            "A one-byte heap overwrite in nginx's DNS resolver can cause a worker crash or, in "
            "some setups, memory disclosure. Fixed in 1.20.1 and 1.21.1."
        ),
        min_inclusive=(0, 6, 18),
        max_exclusive=(1, 21, 1),
    ),
    CveEntry(
        product="tomcat",
        cve="CVE-2020-1938",
        severity=Severity.HIGH,
        title="Apache Tomcat AJP file read / RCE (CVE-2020-1938)",
        summary=(
            "The AJP connector (Ghostcat) lets an attacker read webapp files and, if uploads are "
            "allowed, achieve remote code execution. Fixed in 9.0.31, 8.5.51 and 7.0.100."
        ),
        min_inclusive=(9, 0, 0),
        max_exclusive=(9, 0, 31),
    ),
    CveEntry(
        product="tomcat",
        cve="CVE-2020-1938",
        severity=Severity.HIGH,
        title="Apache Tomcat AJP file read / RCE (CVE-2020-1938)",
        summary="The AJP connector (Ghostcat) permits file read and possible RCE. Fixed in 8.5.51.",
        min_inclusive=(8, 5, 0),
        max_exclusive=(8, 5, 51),
    ),
    CveEntry(
        product="jquery",
        cve="CVE-2020-11022",
        severity=Severity.MEDIUM,
        title="jQuery HTML-parsing XSS (CVE-2020-11022 / CVE-2020-11023)",
        summary=(
            "jQuery's DOM-manipulation methods can execute HTML passed to them, enabling XSS even "
            "after sanitization. Fixed in jQuery 3.5.0."
        ),
        min_inclusive=(1, 0, 0),
        max_exclusive=(3, 5, 0),
    ),
    CveEntry(
        product="drupal",
        cve="CVE-2018-7600",
        severity=Severity.CRITICAL,
        title="Drupal remote code execution 'Drupalgeddon2' (CVE-2018-7600)",
        summary=(
            "A remote attacker can exploit Drupal's Form API to execute arbitrary code. Fixed in "
            "Drupal 7.58, 8.3.9, 8.4.6 and 8.5.1."
        ),
        min_inclusive=(7, 0, 0),
        max_exclusive=(7, 58),
    ),
    CveEntry(
        product="wordpress",
        cve="CVE-2017-1001000",
        severity=Severity.HIGH,
        title="WordPress REST API content injection (CVE-2017-1001000)",
        summary=("The WordPress REST API in 4.7.0-4.7.1 lets unauthenticated users modify any post. Fixed in 4.7.2."),
        min_inclusive=(4, 7, 0),
        max_exclusive=(4, 7, 2),
    ),
    CveEntry(
        product="tomcat",
        cve="CVE-2020-1938",
        severity=Severity.HIGH,
        title="Apache Tomcat AJP file read / RCE (CVE-2020-1938)",
        summary="The AJP connector (Ghostcat) permits file read and possible RCE. Fixed in 7.0.100.",
        min_inclusive=(7, 0, 0),
        max_exclusive=(7, 0, 100),
    ),
    CveEntry(
        product="drupal",
        cve="CVE-2018-7600",
        severity=Severity.CRITICAL,
        title="Drupal remote code execution 'Drupalgeddon2' (CVE-2018-7600)",
        summary=(
            "A remote attacker can exploit Drupal's Form API to execute arbitrary code. Fixed in "
            "Drupal 8.5.1 (and 7.58, 8.3.9, 8.4.6)."
        ),
        min_inclusive=(8, 0, 0),
        max_exclusive=(8, 5, 1),
    ),
    CveEntry(
        product="jquery",
        cve="CVE-2019-11358",
        severity=Severity.MEDIUM,
        title="jQuery prototype pollution (CVE-2019-11358)",
        summary=(
            "jQuery before 3.4.0 copies properties with a deep object-extend that can pollute "
            "Object.prototype, leading to XSS or other client-side impact."
        ),
        min_inclusive=(1, 0, 0),
        max_exclusive=(3, 4, 0),
    ),
)


def parse_tech(token: str) -> tuple[str, tuple[int, ...]] | None:
    """Split a tech/banner token into a lowercase product name and version tuple.

    Returns None when the token carries no parsable ``name version`` pair (for
    example a bare ``Express`` or ``WordPress`` token without a number).
    """
    match = _VERSION_RE.match(token.strip().lower())
    if match is None:
        return None
    name = match.group("name").strip(" .-_")
    version = tuple(int(part) for part in match.group("ver").split(".") if part.isdigit())
    if not name or not version:
        return None
    return name, version


def match_tech(token: str) -> list[CveEntry]:
    """Return every curated CVE whose version condition ``token`` satisfies."""
    parsed = parse_tech(token)
    if parsed is None:
        return []
    name, version = parsed
    hits: list[CveEntry] = []
    for entry in _ENTRIES:
        if not _name_matches(name, entry.product):
            continue
        if entry.exact is not None:
            if version == entry.exact:
                hits.append(entry)
            continue
        if entry.min_inclusive is not None and not _ge(version, entry.min_inclusive):
            continue
        if entry.max_exclusive is not None and not _lt(version, entry.max_exclusive):
            continue
        hits.append(entry)
    return hits


def _name_matches(name: str, product: str) -> bool:
    """Match a parsed product name against an entry's product key.

    Banner names often carry several words ("Apache Tomcat") or vendor
    prefixes/separators ("microsoft-iis"), so a match is any delimited word
    equal to the product key.
    """
    return product in re.split(r"[ ._+-]+", name)


def _pad(version: tuple[int, ...], length: int) -> tuple[int, ...]:
    return version + (0,) * (length - len(version))


def _lt(left: tuple[int, ...], right: tuple[int, ...]) -> bool:
    length = max(len(left), len(right))
    return _pad(left, length) < _pad(right, length)


def _ge(left: tuple[int, ...], right: tuple[int, ...]) -> bool:
    length = max(len(left), len(right))
    return _pad(left, length) >= _pad(right, length)
