"""Report writers for the three -o formats: JSON, Markdown, and plain text.

Shaidra writes no files by default. These writers run only when the CLI was
given an -o flag, and the output directory is created inside `write_reports`
at that moment - never implicitly anywhere else.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, NamedTuple

from shaidra.core.models import Finding, JsonValue, SEVERITY_RANK, ScanContext, Severity
from shaidra.output.theme import SEVERITY_ORDER

_KNOWN_FORMATS: Final[frozenset[str]] = frozenset({"json", "markdown", "txt"})


class _Timeline(NamedTuple):
    """Wall-clock scan bounds, derived from the monotonic run timer."""

    start: str
    end: str
    duration: float


def write_reports(ctx: ScanContext, formats: set[str], outdir: Path, base_name: str) -> list[Path]:
    """Write the requested report formats into `outdir` and return their paths.

    Findings are ordered most-severe-first via SEVERITY_RANK in every format.
    """
    unknown = formats - _KNOWN_FORMATS
    if unknown:
        raise ValueError(f"unknown report format(s): {', '.join(sorted(unknown))}")
    if not formats:
        return []
    outdir.mkdir(parents=True, exist_ok=True)
    findings = sorted(ctx.findings, key=lambda item: SEVERITY_RANK[item.severity], reverse=True)
    timeline = _timeline(ctx)
    written: list[Path] = []
    if "json" in formats:
        written.append(_write(outdir, base_name, ".json", _render_json(ctx, findings, timeline)))
    if "markdown" in formats:
        written.append(_write(outdir, base_name, ".md", _render_markdown(ctx, findings, timeline)))
    if "txt" in formats:
        written.append(_write(outdir, base_name, ".txt", _render_txt(ctx, findings, timeline)))
    return written


def _write(outdir: Path, base_name: str, suffix: str, text: str) -> Path:
    path = outdir / f"{base_name}{suffix}"
    path.write_text(text, encoding="utf-8")
    return path


def _timeline(ctx: ScanContext) -> _Timeline:
    end = datetime.now(UTC)
    elapsed = max(0.0, time.monotonic() - ctx.start_time) if ctx.start_time > 0.0 else 0.0
    start = end - timedelta(seconds=elapsed)
    return _Timeline(start=start.isoformat(), end=end.isoformat(), duration=round(elapsed, 3))


def _severity_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts = dict.fromkeys(Severity, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def _groups(findings: list[Finding]) -> list[tuple[Severity, list[Finding]]]:
    grouped: list[tuple[Severity, list[Finding]]] = []
    for severity in SEVERITY_ORDER:
        group = [item for item in findings if item.severity is severity]
        if group:
            grouped.append((severity, group))
    return grouped


def _metadata_rows(ctx: ScanContext, timeline: _Timeline) -> list[tuple[str, str]]:
    tools = ctx.available_tools
    available = sum(1 for found in tools.values() if found)
    return [
        ("Target", ctx.target),
        ("URL", ctx.target_url),
        ("Mode", ctx.mode),
        ("Started", timeline.start),
        ("Finished", timeline.end),
        ("Duration", f"{timeline.duration:g}s"),
        ("WAF", ctx.waf if ctx.waf is not None else "not detected"),
        ("Extended", "yes" if ctx.extended else "no"),
        ("Rate limit", f"{ctx.rate_limit} req/s"),
        ("Categories", ", ".join(category.value for category in sorted(ctx.categories))),
        ("Tools available", f"{available}/{len(tools)}"),
        ("Hosts", f"{len(ctx.hosts)} total, {len(ctx.live_hosts())} live"),
    ]


def _finding_fields(finding: Finding) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = [
        ("Host", finding.host),
        ("Category", finding.category.value),
        ("Tool", finding.tool),
    ]
    optional = (
        ("URL", finding.url),
        ("CVE", finding.cve),
        ("Description", finding.description),
        ("Evidence", finding.evidence),
        ("References", finding.reference),
    )
    fields.extend((label, value) for label, value in optional if value)
    return fields


def _render_json(ctx: ScanContext, findings: list[Finding], timeline: _Timeline) -> str:
    counts = _severity_counts(findings)
    document: dict[str, JsonValue] = {
        "target": {"host": ctx.target, "url": ctx.target_url},
        "scan": {
            "mode": ctx.mode,
            "extended": ctx.extended,
            "waf": ctx.waf,
            "rate_limit": ctx.rate_limit,
            "categories": [category.value for category in sorted(ctx.categories)],
            "start": timeline.start,
            "end": timeline.end,
            "duration_seconds": timeline.duration,
            "tools_available": {name: found for name, found in sorted(ctx.available_tools.items())},
        },
        "hosts": [host.to_dict() for host in sorted(ctx.hosts.values(), key=lambda item: item.host)],
        "findings": [_finding_payload(finding) for finding in findings],
        "summary": {"total": len(findings), "by_severity": {sev.value: counts[sev] for sev in SEVERITY_ORDER}},
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def _finding_payload(finding: Finding) -> dict[str, JsonValue]:
    record = finding.to_dict()
    record["raw"] = _json_safe(record["raw"])
    return record


def _json_safe(value: JsonValue) -> JsonValue:
    """Recursively keep JSON-native types; convert anything else with str()."""
    match value:
        case str() | int() | float() | bool() | None:
            return value
        case list():
            return [_json_safe(item) for item in value]
        case dict():
            return {str(key): _json_safe(item) for key, item in value.items()}
        case _:
            return str(value)


def _render_markdown(ctx: ScanContext, findings: list[Finding], timeline: _Timeline) -> str:
    counts = _severity_counts(findings)
    lines: list[str] = [f"# Shaidra Scan Report - {ctx.target}", "", "## Scan metadata", ""]
    lines.extend(f"- **{label}:** {value}" for label, value in _metadata_rows(ctx, timeline))
    lines += ["", "## Severity summary", "", "| Severity | Count |", "| --- | ---: |"]
    lines += [f"| {severity.value.upper()} | {counts[severity]} |" for severity in SEVERITY_ORDER]
    lines += [f"| **Total** | **{len(findings)}** |", "", "## Findings", ""]
    if not findings:
        lines.append("_No findings._")
    for severity, group in _groups(findings):
        lines.append(f"### {severity.value.upper()}")
        lines.append("")
        for finding in group:
            lines += [f"#### {finding.title}", ""]
            lines.extend(f"- **{label}:** {value}" for label, value in _finding_fields(finding))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _render_txt(ctx: ScanContext, findings: list[Finding], timeline: _Timeline) -> str:
    counts = _severity_counts(findings)
    meta_rows = _metadata_rows(ctx, timeline)
    meta_width = max(len(label) for label, _ in meta_rows)
    field_width = max((len(label) for item in findings for label, _ in _finding_fields(item)), default=10)
    title = f"SHAIDRA SCAN REPORT - {ctx.target}"
    lines = [title, "=" * len(title), ""]
    lines += [f"{label:<{meta_width}}  {value}" for label, value in meta_rows]
    lines += ["", "SEVERITY SUMMARY", "-" * 17]
    lines += [f"{severity.value.upper():<10}  {counts[severity]:>4}" for severity in SEVERITY_ORDER]
    lines += [f"{'TOTAL':<10}  {len(findings):>4}", "", "FINDINGS", "-" * 8]
    if not findings:
        lines.append("No findings.")
    for severity, group in _groups(findings):
        lines.append(f"{severity.value.upper()} ({len(group)})")
        for finding in group:
            lines.append(f"  {finding.title}")
            lines.extend(f"    {label:<{field_width}}  {value}" for label, value in _finding_fields(finding))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"
