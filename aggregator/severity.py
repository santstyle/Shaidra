"""Severity normalization and ordering for aggregated findings.

Pure helpers that funnel every severity payload a tool can emit (label
strings, CVSS scores, missing values) into the closed ``Severity`` enum, and
sort finished findings most-severe-first for the renderer and report writers.
"""

from __future__ import annotations

import math

from shaidra.core.models import SEVERITY_RANK, Finding, Severity


def normalize_severity(value: str | int | float | None) -> Severity:
    """Map a raw severity payload from any tool onto the ``Severity`` enum.

    Strings are matched case-insensitively against severity labels (including
    ``moderate`` and ``informational``); an unrecognized label, an empty
    string, or ``None`` becomes ``Severity.UNKNOWN``. A boolean is treated as
    an unrecognized payload, not as a score. Numeric input is read as a CVSS
    base score.
    """
    match value:
        case None:
            return Severity.UNKNOWN
        case bool():
            return Severity.UNKNOWN
        case str() as text:
            return _severity_from_label(text)
        case int() | float() as score:
            return severity_from_cvss(float(score))


def _severity_from_label(text: str) -> Severity:
    """Map a free-form severity label to its enum member."""
    match text.strip().casefold():
        case "critical" | "crit":
            return Severity.CRITICAL
        case "high":
            return Severity.HIGH
        case "medium" | "moderate":
            return Severity.MEDIUM
        case "low":
            return Severity.LOW
        case "info" | "informational":
            return Severity.INFO
        case _:
            return Severity.UNKNOWN


def severity_from_cvss(score: float) -> Severity:
    """Bin a CVSS base score onto the ``Severity`` enum.

    Bins: ``>= 9.0`` critical, ``>= 7.0`` high, ``>= 4.0`` medium,
    ``> 0`` low, ``<= 0`` info. Non-finite scores (NaN, +/-inf) and negative
    scores fall back to info; scores above 10 clamp to critical.
    """
    if not math.isfinite(score):
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def findings_by_severity(findings: list[Finding]) -> list[Finding]:
    """Return a new list ordered most severe first by ``SEVERITY_RANK``.

    The sort is stable: findings of equal severity keep their input order,
    and the input list is never mutated.
    """
    return sorted(
        findings,
        key=lambda finding: SEVERITY_RANK[finding.severity],
        reverse=True,
    )
