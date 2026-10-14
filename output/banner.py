"""The SHAIDRA ASCII banner, Dragoncrest logo, and tagline."""

from __future__ import annotations

import os
from typing import Final

from rich.align import Align
from rich.console import Console
from rich.style import Style
from rich.text import Text

from shaidra import __version__
from shaidra.output.logo_art import LOGO_CELLS, LOGO_HEIGHT, LOGO_WIDTH
from shaidra.output.theme import BRAND_ACCENT, BRAND_PRIMARY

_ART: Final[tuple[str, ...]] = (
    " ███████╗██╗  ██╗ █████╗ ██╗██████╗ ██████╗  █████╗",
    " ██╔════╝██║  ██║██╔══██╗██║██╔══██╗██╔══██╗██╔══██╗",
    " ███████╗███████║███████║██║██║  ██║██████╔╝███████║",
    " ╚════██║██╔══██║██╔══██║██║██║  ██║██╔══██╗██╔══██║",
    " ███████║██║  ██║██║  ██║██║██████╔╝██║  ██║██║  ██║",
    " ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝",
)

# Re-export for callers that need the logo dimensions (dashboard header sizing).
LOGO_SIZE: Final[tuple[int, int]] = (LOGO_WIDTH, LOGO_HEIGHT)


def banner_text() -> Text:
    """Return the ASCII block-letter banner as a single styled Text block."""
    text = Text(no_wrap=True)
    for index, line in enumerate(_ART):
        if index:
            text.append("\n")
        text.append(line, style=f"bold {BRAND_PRIMARY}")
    return text


def logo_art_text() -> Text:
    """Return the half-block Dragoncrest logo as a truecolor Text block.

    Each cell is a U+2580 upper-half block whose foreground is the upper
    pixel and background the lower pixel, both taken from the pre-rendered
    cell data. Rich applies per-cell Color objects so it can degrade
    truecolor to 256/16-color automatically on older terminals — never
    embed raw ANSI escape codes in a Text string, Rich does not parse them
    and the terminal mangles the result.
    """
    text = Text(no_wrap=True)
    for index, row in enumerate(LOGO_CELLS):
        if index:
            text.append("\n")
        for upper, lower in row:
            text.append(
                "▀",
                style=Style(
                    color=f"rgb({upper[0]},{upper[1]},{upper[2]})",
                    bgcolor=f"rgb({lower[0]},{lower[1]},{lower[2]})",
                ),
            )
    return text


def logo_art_text_sampled(target_rows: int = 5) -> Text:
    """Return a vertically-sampled version of the logo at reduced height.

    The full logo is 10 half-block rows tall. Space-constrained surfaces
    (TUI header) sample evenly-spaced rows so the crest still reads at
    ~half the vertical cost.
    """
    total = len(LOGO_CELLS)
    if target_rows >= total:
        return logo_art_text()
    indices = [0] if target_rows <= 1 else [round(i * (total - 1) / (target_rows - 1)) for i in range(target_rows)]
    text = Text(no_wrap=True)
    for row_index, index in enumerate(indices):
        if row_index:
            text.append("\n")
        for upper, lower in LOGO_CELLS[index]:
            text.append(
                "▀",
                style=Style(
                    color=f"rgb({upper[0]},{upper[1]},{upper[2]})",
                    bgcolor=f"rgb({lower[0]},{lower[1]},{lower[2]})",
                ),
            )
    return text


def tagline_text() -> Text:
    """Return the versioned tagline shown beneath the banner."""
    return Text(f"deep web vuln scanner · v{__version__}", style=BRAND_ACCENT)


def _supports_truecolor(console: Console) -> bool:
    """Best-effort check for 24-bit color support."""
    if console.no_color:
        return False
    color_system = getattr(console, "color_system", None)
    if color_system in ("truecolor", "256"):
        return True
    # Windows Terminal / modern conhost report truecolor via env.
    return bool(os.environ.get("WT_SESSION") or os.environ.get("ANSICON"))


def render_banner(console: Console) -> None:
    """Print the banner and tagline to the console.

    Wide enough truecolor terminals get the half-block Dragoncrest logo;
    everything else falls back to the classic ASCII block letters.
    """
    use_logo = _supports_truecolor(console) and console.width >= LOGO_WIDTH + 4
    if use_logo:
        console.print(Align.center(logo_art_text()))
    else:
        console.print(Align.center(banner_text()))
    console.print(Align.center(tagline_text()))
    console.print()
