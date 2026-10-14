"""Full-screen Textual TUI for live scan monitoring.

When stdout is an interactive terminal, Shaidra launches this TUI instead of
the plain Rich live view. The TUI owns the whole screen (like htop): findings
and the live feed scroll independently, the header carries the Dragoncrest
logo, and the completion summary stays on screen until the operator quits.
"""

from __future__ import annotations

import os
import sys

__all__ = ["run_tui", "should_launch_tui"]


def should_launch_tui(*, quiet: bool) -> bool:
    """Report whether the full-screen TUI should replace the plain renderer."""
    if quiet:
        return False
    if not sys.stdout.isatty():
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    try:
        import textual  # noqa: F401
    except ImportError:
        return False
    return True


def run_tui(ctx, *, formats: set[str], outdir, base_name: str, scope_file: str | None = None) -> None:
    """Launch the full-screen TUI and block until the operator exits."""
    from shaidra.tui.app import ShaidraApp

    app = ShaidraApp(ctx, formats=formats, outdir=outdir, base_name=base_name, scope_file=scope_file)
    app.run()
