"""The SHAIDRA ASCII banner and tagline."""

from __future__ import annotations

from typing import Final

from rich.align import Align
from rich.console import Console
from rich.text import Text

from shaidra import __version__
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


def tagline_text() -> Text:
    """Return the versioned tagline shown beneath the banner."""
    return Text(f"deep web vuln scanner · v{__version__}", style=BRAND_ACCENT)


def render_banner(console: Console) -> None:
    """Print the banner and tagline to the console."""
    console.print(Align.center(banner_text()))
    console.print(Align.center(tagline_text()))
    console.print()
