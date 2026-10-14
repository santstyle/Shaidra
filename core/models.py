"""Domain models shared across every Shaidra pipeline stage.

These types are the contract between stages, the event bus, the renderer, and
the report writers. They are intentionally dependency-free (no imports from
other Shaidra modules at runtime) so any stage can import them cheaply.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from shaidra.core.config import Config
    from shaidra.core.scope import Scope

JsonValue = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]


class Severity(StrEnum):
    """Normalized finding severity. Rendering colors are mapped in output.theme."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.UNKNOWN: 0,
}


class Category(StrEnum):
    """Scan categories selectable through --categories."""

    RECON = "recon"
    TAKEOVER = "takeover"
    CONTENT = "content"
    WEBVULN = "webvuln"
    CORS = "cors"
    REDIRECT = "redirect"
    JWT = "jwt"
    API = "api"
    CMS = "cms"
    MISCONFIG = "misconfig"
    CVE = "cve"
    SECRETS = "secrets"


ALL_CATEGORIES: Final[tuple[Category, ...]] = tuple(Category)


class StageStatus(StrEnum):
    """Lifecycle state reported by a stage to the renderer."""

    START = "start"
    PROGRESS = "progress"
    DONE = "done"
    SKIP = "skip"
    WARN = "warn"


class LogLevel(StrEnum):
    """Severity of a free-form status line (not a finding)."""

    INFO = "info"
    SUCCESS = "success"
    WARN = "warn"
    ERROR = "error"


def utc_now_iso() -> str:
    """Return the current time as an ISO-8601 string in UTC."""
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)  # noqa: MUTABLE_OK - enriched incrementally across recon and fingerprint stages
class Host:
    """A discovered host and the facts gathered about it during the scan."""

    host: str
    url: str | None = None
    ip: str | None = None
    port: int | None = None
    scheme: str | None = None
    status_code: int | None = None
    title: str | None = None
    server: str | None = None
    content_length: int | None = None
    tech: list[str] = field(default_factory=list)
    cdn: bool = False
    is_live: bool = False
    source: str | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        """Serialize the host for the JSON report."""
        return {
            "host": self.host,
            "url": self.url,
            "ip": self.ip,
            "port": self.port,
            "scheme": self.scheme,
            "status_code": self.status_code,
            "title": self.title,
            "server": self.server,
            "content_length": self.content_length,
            "tech": list(self.tech),
            "cdn": self.cdn,
            "is_live": self.is_live,
            "source": self.source,
        }


@dataclass(slots=True)
class Finding:
    """A single normalized finding produced by any stage."""

    title: str
    severity: Severity
    category: Category
    host: str
    tool: str
    evidence: str = ""
    url: str | None = None
    description: str = ""
    reference: str | None = None
    cve: str | None = None
    template: str | None = None
    raw: dict[str, JsonValue] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> dict[str, JsonValue]:
        """Serialize the finding for the JSON report."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "host": self.host,
            "tool": self.tool,
            "url": self.url,
            "evidence": self.evidence,
            "description": self.description,
            "reference": self.reference,
            "cve": self.cve,
            "template": self.template,
            "timestamp": self.timestamp,
            "raw": dict(self.raw),
        }


@dataclass(slots=True)
class FormTarget:
    """A server-rendered HTML form the built-in web-vuln engine can submit.

    Recorded by the spider so the web-vuln stage can probe forms that only
    respond to GET or POST bodies, which query-string-only probes miss.
    """

    page_url: str
    action_url: str
    method: str
    fields: dict[str, str]
    has_csrf_token: bool = False

    def to_dict(self) -> dict[str, JsonValue]:
        """Serialize the form target for the JSON report."""
        return {
            "page_url": self.page_url,
            "action_url": self.action_url,
            "method": self.method,
            "fields": dict(self.fields),
            "has_csrf_token": self.has_csrf_token,
        }


@dataclass(slots=True)  # noqa: MUTABLE_OK - accumulator mutated by every pipeline stage
class ScanContext:
    """Mutable run state threaded through every stage.

    Mutation is the documented purpose: recon populates hosts, fingerprint
    enriches them, and the renderer accumulates findings for the final report.
    """

    target: str
    target_url: str
    mode: str
    categories: set[Category]
    rate_limit: int
    extended: bool
    scope: Scope
    config: Config
    verbose: bool = False
    quiet: bool = False
    install_tools: bool = False
    hosts: dict[str, Host] = field(default_factory=dict)
    crawled_urls: list[str] = field(default_factory=list)
    form_targets: list[FormTarget] = field(default_factory=list)
    available_tools: dict[str, bool] = field(default_factory=dict)
    waf: str | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    start_time: float = 0.0
    web_reachable: bool = False

    def add_host(self, host: Host) -> Host:
        """Merge a host into the context, keeping any facts already known.

        Later stages enrich earlier hosts (status code, tech, title), so an
        existing entry is updated field-by-field rather than replaced.
        """
        existing = self.hosts.get(host.host)
        if existing is None:
            self.hosts[host.host] = host
            return host
        _merge_host(existing, host)
        return existing

    def live_hosts(self) -> list[Host]:
        """Return only the hosts confirmed live by httpx."""
        return [h for h in self.hosts.values() if h.is_live]

    def has_tool(self, name: str) -> bool:
        """Report whether an external tool was found on PATH."""
        return self.available_tools.get(name, False)

    @property
    def deep(self) -> bool:
        """Whether deep mode is active, widening per-stage coverage budgets."""
        return self.mode == "deep"

    def scale(self, quick: int, deep: int) -> int:
        """Return the deep budget in deep mode, otherwise the quick one."""
        return deep if self.deep else quick


def _merge_host(target: Host, incoming: Host) -> None:
    """Copy populated fields from incoming onto target without clobbering known values."""
    for name in ("url", "ip", "port", "scheme", "status_code", "title", "server", "content_length", "source"):
        if getattr(target, name) is None and getattr(incoming, name) is not None:
            setattr(target, name, getattr(incoming, name))
    for tech in incoming.tech:
        if tech not in target.tech:
            target.tech.append(tech)
    target.cdn = target.cdn or incoming.cdn
    target.is_live = target.is_live or incoming.is_live
