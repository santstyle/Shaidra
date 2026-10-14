"""Brand palette and semantic severity colors for all terminal output.

Two color systems are used on purpose:

* **Chrome** (banner, borders, rules, section labels) uses the brand's fixed
  dark-purple hex. Purple is a *dark* hue, so it stays legible on both light and
  dark backgrounds, and Rich downgrades it automatically on 256/16-color
  terminals. It is deliberately purple - never magenta/pink.
* **Body text** uses the terminal's default foreground so it can never clash
  with the user's background. Severity uses named ANSI colors so the terminal's
  own palette keeps them readable on light or dark themes.

Severity colors are semantic and must never be replaced by brand colors, so a
CRITICAL finding always reads red regardless of theme.
"""

from __future__ import annotations

from typing import Final

from rich.style import Style

from shaidra.core.models import LogLevel, Severity

BRAND_PRIMARY: Final[str] = "#6D28D9"  # dark purple
BRAND_DARK: Final[str] = "#1A1025"  # near-black purple
BRAND_ACCENT: Final[str] = "#8B5CF6"  # medium violet
BRAND_MUTED: Final[str] = "#4A4458"  # dark grey-purple

SEVERITY_CRITICAL: Final[str] = "bright_red"
SEVERITY_HIGH: Final[str] = "red"
SEVERITY_MEDIUM: Final[str] = "yellow"
SEVERITY_LOW: Final[str] = "cyan"
SEVERITY_INFO: Final[str] = "bright_black"

# ``default`` follows the terminal's foreground, so primary text never clashes
# with the user's background color.
TEXT_PRIMARY: Final[str] = "default"
TEXT_MUTED: Final[str] = "bright_black"
TEXT_SUCCESS: Final[str] = "green"

SEVERITY_COLORS: Final[dict[Severity, str]] = {
    Severity.CRITICAL: SEVERITY_CRITICAL,
    Severity.HIGH: SEVERITY_HIGH,
    Severity.MEDIUM: SEVERITY_MEDIUM,
    Severity.LOW: SEVERITY_LOW,
    Severity.INFO: SEVERITY_INFO,
    Severity.UNKNOWN: SEVERITY_INFO,
}

LOG_COLORS: Final[dict[LogLevel, str]] = {
    LogLevel.INFO: "cyan",
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

# --- Dashboard palette ------------------------------------------------------
# The full-screen live dashboard paints its own dark-purple surface, so it
# cannot rely on the terminal's default foreground (unreadable on light user
# themes once placed on the dark background). Every dashboard color is an
# explicit hex; the fallback/piped path above keeps using ANSI/default styles.

DASH_BG_PAGE: Final[str] = "#0B0713"  # near-black purple page background
DASH_BG_PANEL: Final[str] = "#120C20"  # panel fill
DASH_BORDER: Final[str] = "#4C1D95"  # deep violet panel borders
DASH_TITLE: Final[str] = "#A78BFA"  # panel titles
DASH_ACCENT: Final[str] = "#8B5CF6"  # bars, active dots
DASH_ACCENT_BRIGHT: Final[str] = "#C4B5FD"  # finished bars, highlights
DASH_BAR_TRACK: Final[str] = "#2A1F45"  # empty bar / donut gap
DASH_TEXT: Final[str] = "#E6E1F2"  # primary text on the dark surface
DASH_DIM: Final[str] = "#8B82AD"  # secondary text
DASH_OK: Final[str] = "#34D399"  # success checkmarks

# Severity hexes for the dashboard surface; semantics unchanged (critical
# stays the worst color) but tuned for contrast against DASH_BG_PANEL.
DASH_SEVERITY_COLORS: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "#F43F5E",
    Severity.HIGH: "#F59E0B",
    Severity.MEDIUM: "#3B82F6",
    Severity.LOW: "#A855F7",
    Severity.INFO: "#94A3B8",
    Severity.UNKNOWN: "#94A3B8",
}


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
