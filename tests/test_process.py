"""Tests for subprocess helpers (stream_lines oversized-line handling)."""

from __future__ import annotations

import asyncio
import sys

from shaidra.utils.process import RunOptions, stream_lines


def test_stream_lines_skips_oversized_line_and_keeps_rest() -> None:
    """A single physical line past the StreamReader limit must not abort.

    Tools like katana emit minified-JS URLs as one huge line; asyncio's
    readline() raises ValueError past the buffer limit. stream_lines must
    skip that line and continue yielding subsequent lines.
    """

    async def collect() -> list[str]:
        # Emit a small line, then a 2 MiB line (past the 1 MiB subprocess
        # limit), then another small line — all via stdin so Windows
        # command-length limits never apply.
        huge = "x" * (2 * 1024 * 1024)
        script = f"import sys\nsys.stdout.write('first\\n{huge}\\nlast\\n')\nsys.stdout.flush()\n"
        return [
            line
            async for line in stream_lines([sys.executable, "-u", "-"], RunOptions(timeout=15.0, input_text=script))
        ]

    lines = asyncio.run(collect())
    assert "first" in lines
    assert "last" in lines
    assert not any(len(line) > 1024 * 1024 for line in lines)
