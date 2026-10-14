"""Tests for subprocess helpers (stream_lines oversized-line handling, cancellation cleanup)."""

from __future__ import annotations

import asyncio
import sys

import pytest

import shaidra.utils.process as process_mod
from shaidra.utils.process import RunOptions, run_tool, stream_lines


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


def test_run_tool_kills_child_on_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cancelling run_tool mid-execution must kill the child, not leak it.

    On Windows the Proactor event loop leaves pipe transports attached to an
    unclosed subprocess; at interpreter exit their __del__ raises
    ``ValueError: I/O operation on closed pipe`` (the Ctrl+C crash). The
    CancelledError handler in run_tool must reap the child before re-raising.
    """

    killed: list[asyncio.subprocess.Process] = []
    original_kill = process_mod._kill

    async def tracking_kill(proc: asyncio.subprocess.Process) -> None:
        killed.append(proc)
        await original_kill(proc)

    monkeypatch.setattr(process_mod, "_kill", tracking_kill)

    async def scenario() -> None:
        task = asyncio.create_task(run_tool([sys.executable, "-c", "import time; time.sleep(30)"]))
        await asyncio.sleep(0.5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(scenario())
    assert len(killed) == 1, "child must be killed on cancellation"
