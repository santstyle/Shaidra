"""WAF fingerprinting, run before the heavy stages to tune the rate limit.

Prefers wafw00f when installed and falls back to a header-signature heuristic
using Shaidra's own HTTP client, so the pipeline still adapts when wafw00f is
absent.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from typing import Final

import httpx

from shaidra.core.events import EventBus
from shaidra.core.models import JsonValue, LogLevel, ScanContext
from shaidra.utils.process import RunOptions, run_tool

STAGE_NAME: Final[str] = "WAF detection"
_HTTP_TIMEOUT: Final[float] = 10.0
_WAFW00F_TIMEOUT: Final[int] = 120

# Header signatures are matched against a lowercased "key:value" blob.
_HEADER_SIGNATURES: Final[dict[str, tuple[str, ...]]] = {
    "Cloudflare": ("cf-ray", "server:cloudflare"),
    "Akamai": ("x-akamai", "akamaighost"),
    "AWS WAF": ("awselb", "x-amz-cf-id", "x-amzn-requestid"),
    "Sucuri": ("x-sucuri-id", "x-sucuri-cache"),
    "Imperva": ("x-iinfo", "visid_incap", "incap_ses"),
    "F5 BIG-IP": ("x-wa-info", "bigipserver", "ts01"),
    "Fastly": ("x-served-by", "fastly"),
}


async def detect_waf(ctx: ScanContext, bus: EventBus) -> str | None:
    """Detect a WAF in front of the target; return its name or None."""
    await bus.stage_start(STAGE_NAME)
    name: str | None = None
    if ctx.has_tool("wafw00f"):
        name = await _via_wafw00f(ctx)
    if name is None:
        name = await _via_headers(ctx)
    if name is not None:
        await bus.log(f"WAF detected: {name}, lowering request rate", LogLevel.WARN)
        await bus.stage_done(STAGE_NAME, name)
    else:
        await bus.stage_done(STAGE_NAME, "none")
    return name


async def _via_wafw00f(ctx: ScanContext) -> str | None:
    """Run wafw00f, reading its JSON report from a temp file.

    wafw00f's ``-o -`` (write to stdout) does not work on Windows — it creates a
    file named ``-`` in the working directory and leaves stdout empty — so the
    report is always written to a temp file and read back from there.
    """
    handle, report = tempfile.mkstemp(prefix="shaidra-wafw00f-", suffix=".json")
    os.close(handle)
    try:
        argv = ["wafw00f", ctx.target_url, "-f", "json", "-o", report]
        options = RunOptions(timeout=ctx.config.timeout_for("wafw00f", _WAFW00F_TIMEOUT))
        result = await run_tool(argv, options)
        stdout = _read_report(report).strip() or result.stdout.strip()
        if not stdout:
            return None
        return _parse_wafw00f(stdout)
    finally:
        with contextlib.suppress(OSError):
            os.remove(report)


def _read_report(path: str) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _parse_wafw00f(stdout: str) -> str | None:
    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError:
        return _parse_wafw00f_text(stdout)
    return _first_detected_firewall(payload)


def _first_detected_firewall(payload: JsonValue) -> str | None:
    if isinstance(payload, list):
        for entry in payload:
            name = _firewall_name(entry)
            if name is not None:
                return name
    return _firewall_name(payload)


def _firewall_name(entry: JsonValue) -> str | None:
    if not isinstance(entry, dict):
        return None
    detected = entry.get("detected")
    firewall = entry.get("firewall")
    if detected is True and isinstance(firewall, str) and firewall.lower() != "none":
        return firewall
    return None


def _parse_wafw00f_text(stdout: str) -> str | None:
    for line in stdout.splitlines():
        lowered = line.lower()
        if "is behind" in lowered:
            return line.split("is behind", 1)[1].strip().rstrip(".") or None
    return None


async def _via_headers(ctx: ScanContext) -> str | None:
    for url in _candidate_urls(ctx.target_url):
        blob = await _header_blob(url)
        if blob is None:
            continue
        for name, needles in _HEADER_SIGNATURES.items():
            if any(needle in blob for needle in needles):
                return name
    return None


def _candidate_urls(target_url: str) -> list[str]:
    """Return the target URL and its opposite-scheme sibling to probe both."""
    if target_url.startswith("https://"):
        return [target_url, f"http://{target_url[len('https://') :]}"]
    if target_url.startswith("http://"):
        return [target_url, f"https://{target_url[len('http://') :]}"]
    return [f"https://{target_url}", f"http://{target_url}"]


async def _header_blob(url: str) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            response = await client.get(url)
    except httpx.HTTPError:
        return None
    return " ".join(f"{key}:{value}".lower() for key, value in response.headers.items())
