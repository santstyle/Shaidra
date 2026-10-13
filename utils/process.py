"""Async execution of external security tools.

Every external tool is invoked through a subprocess. A missing binary is never
a crash: `run_tool` and `stream_lines` degrade to a 127 result or an empty
stream so the owning stage can skip gracefully.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

TOOL_NOT_FOUND_RC: Final[int] = 127
TIMEOUT_RC: Final[int] = -1


@dataclass(frozen=True, slots=True)
class RunOptions:
    """Optional execution knobs for a single tool invocation."""

    timeout: float | None = None
    input_text: str | None = None
    cwd: str | None = None
    env: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Captured result of a finished tool invocation."""

    tool: str
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        """True when the tool exited zero."""
        return self.returncode == 0

    @property
    def missing(self) -> bool:
        """True when the tool was not found on PATH."""
        return self.returncode == TOOL_NOT_FOUND_RC


def tool_available(name: str) -> bool:
    """Return whether `name` resolves to an executable on PATH."""
    return shutil.which(name) is not None


def check_tools(names: Sequence[str]) -> dict[str, bool]:
    """Return a name to availability map for the given tools."""
    return {name: tool_available(name) for name in names}


async def run_tool(argv: Sequence[str], options: RunOptions | None = None) -> ToolResult:
    """Run a tool to completion and capture stdout/stderr.

    `argv` is the full command line; `argv[0]` is the binary name. Returns a
    127 result when the binary is missing and a -1 result on timeout, in both
    cases without raising.
    """
    opts = options or RunOptions()
    tool = argv[0]
    binary = shutil.which(tool)
    if binary is None:
        return ToolResult(tool=tool, returncode=TOOL_NOT_FOUND_RC, stdout="", stderr=f"{tool} not found on PATH")

    try:
        proc = await _spawn(binary, argv[1:], opts)
    except OSError as exc:
        return ToolResult(tool=tool, returncode=TOOL_NOT_FOUND_RC, stdout="", stderr=str(exc))

    try:
        async with asyncio.timeout(opts.timeout):  # noqa: ANYIO_OK - spec mandates asyncio
            payload = opts.input_text.encode("utf-8") if opts.input_text is not None else None
            stdout_b, stderr_b = await proc.communicate(payload)
    except TimeoutError:
        await _kill(proc)
        return ToolResult(tool=tool, returncode=TIMEOUT_RC, stdout="", stderr=f"timed out after {opts.timeout}s")

    return ToolResult(
        tool=tool,
        returncode=proc.returncode if proc.returncode is not None else TIMEOUT_RC,
        stdout=stdout_b.decode("utf-8", "replace"),
        stderr=stderr_b.decode("utf-8", "replace"),
    )


async def stream_lines(argv: Sequence[str], options: RunOptions | None = None) -> AsyncIterator[str]:
    """Yield decoded stdout lines from a long-running tool as they appear.

    Intended for tools that emit JSONL or streaming text (httpx, nuclei,
    katana, ffuf). stderr is drained concurrently so the child never blocks on
    a full pipe. Yields nothing when the binary is missing.
    """
    opts = options or RunOptions()
    tool = argv[0]
    binary = shutil.which(tool)
    if binary is None:
        return

    try:
        proc = await _spawn(binary, argv[1:], opts)
    except OSError:
        return

    stderr = proc.stderr
    assert stderr is not None  # noqa: S101 - narrowing; stderr is a pipe by construction
    stderr_task = asyncio.create_task(stderr.read())
    try:
        async with asyncio.timeout(opts.timeout):  # noqa: ANYIO_OK - spec mandates asyncio
            await _feed_stdin(proc, opts.input_text)
            stdout = proc.stdout
            assert stdout is not None  # noqa: S101 - narrowing; stdout is a pipe by construction
            async for raw in stdout:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line:
                    yield line
    except TimeoutError:
        pass
    finally:
        await _kill(proc)
        stderr_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await stderr_task


async def _spawn(binary: str, args: Sequence[str], opts: RunOptions) -> asyncio.subprocess.Process:
    """Create the child process with pipes wired for capture or streaming."""
    return await asyncio.create_subprocess_exec(
        binary,
        *args,
        stdin=asyncio.subprocess.PIPE if opts.input_text is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=opts.cwd,
        env=dict(opts.env) if opts.env is not None else None,
    )


async def _feed_stdin(proc: asyncio.subprocess.Process, text: str | None) -> None:
    """Write stdin payload if provided, then close the pipe."""
    if text is None or proc.stdin is None:
        return
    proc.stdin.write(text.encode("utf-8"))
    await proc.stdin.drain()
    proc.stdin.close()


async def _kill(proc: asyncio.subprocess.Process) -> None:
    """Ensure the child is terminated and reaped."""
    if proc.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
    with contextlib.suppress(ProcessLookupError):
        await proc.wait()
