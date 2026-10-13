"""Async event bus connecting pipeline stages to the live terminal renderer.

Stages never touch the terminal directly. They push events onto the bus and a
single consumer (the renderer) drains it, so findings stream to the screen the
moment a stage produces them instead of being batched until every task ends.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from shaidra.core.models import Finding, Host, LogLevel, StageStatus


@dataclass(slots=True)
class LogEvent:
    """A free-form status line, e.g. "Subdomain enum ... done, 40 found"."""

    level: LogLevel
    message: str


@dataclass(slots=True)
class FindingEvent:
    """A normalized finding ready to render and store."""

    finding: Finding


@dataclass(slots=True)
class StageEvent:
    """A stage lifecycle update driving the progress bars."""

    name: str
    status: StageStatus
    current: int = 0
    total: int = 0
    detail: str = ""


@dataclass(slots=True)
class HostEvent:
    """A host discovered or enriched by a stage."""

    host: Host


Event = LogEvent | FindingEvent | StageEvent | HostEvent


class EventBus:
    """Fan-in queue: stages emit, the renderer consumes.

    asyncio is used deliberately because the project spec mandates it for
    parallel subprocess orchestration (# noqa: ANYIO_OK).
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[Event | None] = asyncio.Queue()

    async def emit(self, event: Event) -> None:
        """Push an arbitrary event onto the bus."""
        await self._queue.put(event)

    async def log(self, message: str, level: LogLevel = LogLevel.INFO) -> None:
        """Emit a status line at the given level."""
        await self.emit(LogEvent(level=level, message=message))

    async def finding(self, finding: Finding) -> None:
        """Emit a finding for immediate rendering and accumulation."""
        await self.emit(FindingEvent(finding=finding))

    async def host(self, host: Host) -> None:
        """Emit a discovered or enriched host."""
        await self.emit(HostEvent(host=host))

    async def stage_start(self, name: str) -> None:
        """Mark a stage as started."""
        await self.emit(StageEvent(name=name, status=StageStatus.START))

    async def stage_progress(self, name: str, current: int, total: int) -> None:
        """Report progress within a stage for its progress bar."""
        await self.emit(StageEvent(name=name, status=StageStatus.PROGRESS, current=current, total=total))

    async def stage_done(self, name: str, detail: str = "") -> None:
        """Mark a stage as finished, optionally with a result summary."""
        await self.emit(StageEvent(name=name, status=StageStatus.DONE, detail=detail))

    async def stage_skip(self, name: str, reason: str = "") -> None:
        """Mark a stage as skipped (missing tool, condition not met)."""
        await self.emit(StageEvent(name=name, status=StageStatus.SKIP, detail=reason))

    async def stage_warn(self, name: str, detail: str = "") -> None:
        """Mark a stage as finished with a warning."""
        await self.emit(StageEvent(name=name, status=StageStatus.WARN, detail=detail))

    async def next_event(self) -> Event | None:
        """Block until the next event arrives, or None once the bus is closed."""
        return await self._queue.get()

    async def close(self) -> None:
        """Signal the consumer that no further events will be produced."""
        await self._queue.put(None)
