"""Brand palette and semantic severity colors for all terminal output.

Brand purple is used only for chrome: banner, borders, progress bars, and
section labels. Severity colors are semantic and must never be replaced by
brand colors, so a CRITICAL finding always reads red regardless of theme.
"""

from __future__ import annotations

from typing import Final

from rich.style import Style

from shaidra.core.models import LogLevel, Severity

BRAND_PRIMARY: Final[str] = "#6D28D9"
BRAND_DARK: Final[str] = "#1A1025"
BRAND_ACCENT: Final[str] = "#A78BFA"
BRAND_MUTED: Final[str] = "#4A4458"

SEVERITY_CRITICAL: Final[str] = "#F03E3E"
SEVERITY_HIGH: Final[str] = "#F76707"
SEVERITY_MEDIUM: Final[str] = "#F5C518"
SEVERITY_LOW: Final[str] = "#4DABF7"
SEVERITY_INFO: Final[str] = "#868E96"

TEXT_PRIMARY: Final[str] = "#E5E1F0"
TEXT_MUTED: Final[str] = "#9A93AC"
TEXT_SUCCESS: Final[str] = "#37B24D"

SEVERITY_COLORS: Final[dict[Severity, str]] = {
    Severity.CRITICAL: SEVERITY_CRITICAL,
    Severity.HIGH: SEVERITY_HIGH,
    Severity.MEDIUM: SEVERITY_MEDIUM,
    Severity.LOW: SEVERITY_LOW,
    Severity.INFO: SEVERITY_INFO,
    Severity.UNKNOWN: SEVERITY_INFO,
}

LOG_COLORS: Final[dict[LogLevel, str]] = {
    LogLevel.INFO: BRAND_ACCENT,
    LogLevel.SUCCESS: TEXT_SUCCESS,
    LogLevel.WARN: SEVERITY_MEDIUM,
    LogLevel.ERROR: SEVERITY_CRITICAL,
}

# Display order for the summary line, worst first.
SEVERITY_ORDER: Final[tuple[Severity, ...]] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
)


def severity_color(severity: Severity) -> str:
    """Return the semantic color for a severity level."""
    return SEVERITY_COLORS[severity]


def severity_style(severity: Severity) -> Style:
    """Return a bold style for a severity badge."""
    return Style(color=severity_color(severity), bold=True)


def log_color(level: LogLevel) -> str:
    """Return the color for a status line at the given level."""
    return LOG_COLORS[level]


def brand_style() -> Style:
    """Return the style used for borders, banners, and section titles."""
    return Style(color=BRAND_PRIMARY, bold=True)


def accent_style() -> Style:
    """Return the highlight style for informational text."""
    return Style(color=BRAND_ACCENT)


def muted_style() -> Style:
    """Return the style for secondary detail lines."""
    return Style(color=TEXT_MUTED)


def primary_style() -> Style:
    """Return the style for primary body text."""
    return Style(color=TEXT_PRIMARY)
