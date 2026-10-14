"""The SHAIDRA ASCII banner and tagline."""

from __future__ import annotations

from typing import Final

from rich.align import Align
from rich.console import Console
from rich.text import Text

from shaidra import __version__
from shaidra.output.logo_art import LOGO_ART, LOGO_WIDTH
from shaidra.output.theme import BRAND_ACCENT, BRAND_PRIMARY

_ART: Final[tuple[str, ...]] = (
    " ███████╗██╗  ██╗ █████╗ ██╗██████╗ ██████╗  █████╗",
    " ██╔════╝██║  ██║██╔══██╗██║██╔══██╗██╔══██╗██╔══██╗",
    " ███████╗███████║███████║██║██║  ██║██████╔╝███████║",
    " ╚════██║██╔══██║██╔══██║██║██║  ██║██╔══██╗██╔══██║",
    " ███████║██║  ██║██║  ██║██║██████╔╝██║  ██║██║  ██║",
    " ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝",
)


def banner_text() -> Text:
    """Return the banner art as a single styled Text block."""
    text = Text()
    for line in _ART:
        text.append(f"{line}\n", style=f"bold {BRAND_PRIMARY}")
    return text


def logo_art_text() -> Text:
    """Return the half-block Dragoncrest logo as a Text block.

    Each character carries explicit 24-bit foreground/background colors from
    the pre-rendered art module. Rich renders the ANSI SGR codes as truecolor
    cells; terminals without truecolor support degrade gracefully to the
    nearest palette color (or black-on-black if color is off entirely).
    """
    return Text(LOGO_ART, no_wrap=True)


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
    import os

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
