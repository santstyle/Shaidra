"""CVE matching with nuclei.

Runs nuclei's CVE-tagged templates against every live, in-scope host URL and
normalizes each JSONL match into a Finding with the CVE identifier extracted
from the template classification (falling back to the template ID).
"""

from __future__ import annotations

import contextlib
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from shaidra.core.events import EventBus
from shaidra.core.models import Category, Finding, JsonValue, ScanContext, Severity
from shaidra.utils.process import RunOptions, stream_lines

STAGE_NAME: Final[str] = "CVE matching"


@dataclass(frozen=True, slots=True)
class _CveHit:
    """One parsed nuclei CVE JSONL record."""

    template_id: str
    name: str
    severity: Severity
    host: str
    matched_at: str | None
    cve: str | None
    raw: dict[str, JsonValue]


async def run(ctx: ScanContext, bus: EventBus) -> None:
    """Scan live hosts for known CVEs with nuclei's cve-tagged templates."""
    if not ctx.has_tool("nuclei"):
        await bus.stage_skip(STAGE_NAME, "nuclei is not installed")
        return

    targets = _live_target_urls(ctx)
    if not targets:
        await bus.stage_skip(STAGE_NAME, "no live in-scope hosts to scan")
        return

    await bus.stage_start(STAGE_NAME)
    await bus.stage_progress(STAGE_NAME, 0, len(targets))
    findings = 0
    targets_file = _write_list(targets)
    if targets_file is None:
        await bus.stage_warn(STAGE_NAME, "could not write target list")
        return
    try:
        findings = await _run_nuclei(ctx, bus, targets_file)
    finally:
        _remove(targets_file)
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
    """Stream nuclei CVE results and emit one finding per match."""
    argv = [
        "nuclei",
        "-silent",
        "-jsonl",
        "-tags",
        "cve",
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
        await bus.finding(_cve_finding(hit))
        count += 1
    return count


def _cve_finding(hit: _CveHit) -> Finding:
    """Convert a parsed nuclei record into a CVE finding."""
    matched = hit.matched_at or hit.host
    return Finding(
        title=hit.name,
        severity=hit.severity,
        category=Category.CVE,
        host=hit.host,
        tool="nuclei",
        evidence=matched,
        url=hit.matched_at,
        description=f"Nuclei template {hit.template_id} ({hit.name}) matched {matched}.",
        reference=hit.template_id,
        cve=hit.cve,
        template=hit.template_id,
        raw=dict(hit.raw),
    )


def _parse_nuclei_line(line: str) -> _CveHit | None:
    """Parse one JSONL line into a CVE record, or None for junk lines."""
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    return _nuclei_record_from(payload)


def _nuclei_record_from(payload: JsonValue) -> _CveHit | None:
    """Narrow a parsed JSON value into a CVE record, or None."""
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
    return _CveHit(
        template_id=template_id,
        name=name if isinstance(name, str) and name else template_id,
        severity=_map_severity(info.get("severity")),
        host=host,
        matched_at=matched_at,
        cve=_extract_cve(info) or template_id,
        raw=dict(payload),
    )


def _extract_cve(info: dict[str, JsonValue]) -> str | None:
    """Return the CVE identifier(s) from info.classification.cve-id, if present."""
    classification = info.get("classification")
    if not isinstance(classification, dict):
        return None
    raw = classification.get("cve-id")
    match raw:
        case str():
            return raw if raw else None
        case list():
            ids = [entry for entry in raw if isinstance(entry, str) and entry]
            return ", ".join(ids) if ids else None
        case _:
            return None


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


def _write_list(entries: list[str]) -> Path | None:
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
