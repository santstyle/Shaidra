"""Subdomain takeover detection.

Runs nuclei's takeover-tagged templates against every live, in-scope host URL
and, when subjack is installed and real enumerated subdomains exist, cross-
checks those with subjack's fingerprint database. Both tools are optional; a
missing tool or missing fingerprint file degrades to a stage skip.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, JsonValue, ScanContext, Severity
from shaidra.utils.process import RunOptions, run_tool, stream_lines

STAGE_NAME: Final[str] = "Takeover detection"
_SUBJACK_TIMEOUT: Final[int] = 300
_SUBJACK_LINE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<host>[^\s\[]+)\s+\[(?P<service>[^\]]+)\]\s*:\s*(?P<verdict>.+)$"
)
_SUBJACK_VERDICTS: Final[frozenset[str]] = frozenset({"Vulnerable", "Hijackable"})


@dataclass(frozen=True, slots=True)
class _NucleiTakeover:
    """One parsed nuclei takeover JSONL record."""

    template_id: str
    name: str
    severity: Severity
    host: str
    matched_at: str | None
    raw: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class _SubjackHit:
    """One parsed subjack vulnerable line."""

    host: str
    service: str
    verdict: str


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Check live hosts for dangling-service takeover with nuclei and subjack."""
    has_nuclei = ctx.has_tool("nuclei")
    has_subjack = ctx.has_tool("subjack")
    if not has_nuclei and not has_subjack:
        await bus.stage_skip(STAGE_NAME, "nuclei and subjack are not installed")
        return

    await bus.stage_start(STAGE_NAME)
    targets = _live_target_urls(ctx)
    await bus.stage_progress(STAGE_NAME, 0, len(targets))
    findings = 0
    nuclei_list: Path | None = None
    subdomain_list: Path | None = None
    try:
        if has_nuclei and targets:
            nuclei_list = _write_list(targets)
            if nuclei_list is not None:
                findings += await _run_nuclei(ctx, bus, nuclei_list)
        if has_subjack:
            subdomains = _enumerated_subdomains(ctx)
            fingerprints = _locate_fingerprints()
            if subdomains and fingerprints is not None:
                subdomain_list = _write_list(subdomains)
                if subdomain_list is not None:
                    findings += await _run_subjack(bus, subdomain_list, fingerprints)
    finally:
        _remove(nuclei_list)
        _remove(subdomain_list)
    await bus.stage_done(STAGE_NAME, f"{findings} findings")


def _live_target_urls(ctx: ScanContext) -> list[str]:
    """Return deduplicated, in-scope URLs for every live host."""
    urls: list[str] = []
    for host in ctx.live_hosts():
        url = host.url or f"https://{host.host}"
        if ctx.scope.in_scope(url) and url not in urls:
            urls.append(url)
    return urls


async def _run_nuclei(ctx: ScanContext, bus: EventBus, targets_file: Path) -> int:
    """Stream nuclei takeover results and emit one finding per match."""
    argv = [
        "nuclei",
        "-silent",
        "-jsonl",
        "-tags",
        "takeover",
        "-rate-limit",
        str(ctx.rate_limit),
        "-l",
        str(targets_file),
    ]
    options = RunOptions(timeout=float(ctx.config.timeout_for("nuclei")))
    count = 0
    async for line in stream_lines(argv, options):
        hit = _parse_nuclei_line(line)
        if hit is None or not ctx.scope.in_scope(hit.host):
            continue
        await bus.finding(_nuclei_finding(hit))
        count += 1
    return count


def _nuclei_finding(hit: _NucleiTakeover) -> Finding:
    """Convert a parsed nuclei record into a takeover finding."""
    matched = hit.matched_at or hit.host
    return Finding(
        title=f"Possible takeover: {hit.name}",
        severity=hit.severity,
        category=Category.TAKEOVER,
        host=hit.host,
        tool="nuclei",
        evidence=matched,
        url=hit.matched_at,
        description=f"Nuclei template {hit.template_id} ({hit.name}) matched {matched}.",
        reference=hit.template_id,
        template=hit.template_id,
        raw=dict(hit.raw),
    )


def _parse_nuclei_line(line: str) -> _NucleiTakeover | None:
    """Parse one JSONL line into a takeover record, or None for junk lines."""
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    return _nuclei_record_from(payload)


def _nuclei_record_from(payload: JsonValue) -> _NucleiTakeover | None:
    """Narrow a parsed JSON value into a takeover record, or None."""
    if not isinstance(payload, dict):
        return None
    template_id = payload.get("template-id")
    info = payload.get("info")
    if not isinstance(template_id, str) or not template_id or not isinstance(info, dict):
        return None
    name = info.get("name")
    host = payload.get("host")
    matched = payload.get("matched-at")
    matched_at = matched if isinstance(matched, str) and matched else None
    host_value = host if isinstance(host, str) and host else None
    if host_value is not None:
        host = host_value
    elif matched_at is not None:
        host = matched_at
    else:
        return None
    return _NucleiTakeover(
        template_id=template_id,
        name=name if isinstance(name, str) and name else template_id,
        severity=_map_severity(info.get("severity")),
        host=host,
        matched_at=matched_at,
        raw=dict(payload),
    )


def _map_severity(raw: JsonValue | None) -> Severity:
    """Map a nuclei severity string to the Severity enum; unknown goes to INFO."""
    match raw:
        case "critical":
            return Severity.CRITICAL
        case "high":
            return Severity.HIGH
        case "medium":
            return Severity.MEDIUM
        case "low":
            return Severity.LOW
        case "info":
            return Severity.INFO
        case _:
            return Severity.INFO


def _enumerated_subdomains(ctx: ScanContext) -> list[str]:
    """Return in-scope hostnames beyond the bare target, if any were found."""
    names = sorted({host.host for host in ctx.hosts.values() if ctx.scope.in_scope(host.host)})
    return names if len(names) > 1 else []


def _locate_fingerprints() -> Path | None:
    """Find a usable subjack fingerprints file, or None to skip subjack."""
    override = os.environ.get("SHAIDRA_SUBJACK_FINGERPRINTS")
    candidates = [Path(override)] if override else []
    candidates.append(Path.cwd() / "fingerprints.json")
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


async def _run_subjack(bus: EventBus, subdomains_file: Path, fingerprints: Path) -> int:
    """Run subjack against the subdomain list and emit findings for hijackables."""
    argv = [
        "subjack",
        "-w",
        str(subdomains_file),
        "-t",
        "100",
        "-timeout",
        "30",
        "-ssl",
        "-v",
        "-f",
        str(fingerprints),
    ]
    options = RunOptions(timeout=float(_SUBJACK_TIMEOUT))
    result = await run_tool(argv, options)
    count = 0
    for line in result.stdout.splitlines():
        hit = _parse_subjack_line(line)
        if hit is None:
            continue
        await bus.finding(
            Finding(
                title=f"Possible takeover: {hit.host} ({hit.service})",
                severity=Severity.HIGH,
                category=Category.TAKEOVER,
                host=hit.host,
                tool="subjack",
                evidence=line.strip(),
                description=f"subjack reports {hit.host} as {hit.verdict} via {hit.service}.",
                reference="subjack",
                template=hit.service,
                raw={"line": line.strip()},
            )
        )
        count += 1
    return count


def _parse_subjack_line(line: str) -> _SubjackHit | None:
    """Parse a subjack verdict line, or None when the line is not a hit."""
    match_obj = _SUBJACK_LINE.match(line.strip())
    if match_obj is None:
        return None
    verdict = match_obj.group("verdict")
    if verdict not in _SUBJACK_VERDICTS:
        return None
    return _SubjackHit(
        host=match_obj.group("host"),
        service=match_obj.group("service"),
        verdict=verdict,
    )


def _write_list(entries: Sequence[str]) -> Path | None:
    """Write entries as a newline-delimited temp file, or None on failure."""
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="\n", suffix=".txt", delete=False
        ) as handle:
            handle.write("\n".join(entries))
            handle.write("\n")
            return Path(handle.name)
    except OSError:
        return None


def _remove(path: Path | None) -> None:
    """Delete a temp file if it exists; never raise."""
    if path is None:
        return
    with contextlib.suppress(OSError):
        path.unlink(missing_ok=True)
