"""Target scope parsing and enforcement.

The scope decides which discovered hostnames a stage is allowed to touch.
When the user supplies a scope file, anything outside the listed rules is
skipped from active scanning (not merely warned about). Without a scope file,
the target domain and its subdomains are in scope, which is what subdomain
enumeration exists to explore.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

COMMENT_PREFIXES = ("#", ";")


class ScopeError(Exception):
    """Raised when a scope file cannot be read or yields no usable rules."""


_HTTP_PORTS: frozenset[int] = frozenset({80, 3000, 5000, 8000, 8080, 8888})


@dataclass(frozen=True, slots=True)
class TargetSpec:
    """A parsed scan target: scheme, host, and optional port."""

    scheme: str
    host: str
    port: int | None = None

    @property
    def host_port(self) -> str:
        """Return the host with its port, when one is present."""
        return f"{self.host}:{self.port}" if self.port is not None else self.host

    @property
    def url(self) -> str:
        """Return the base URL for the target."""
        return f"{self.scheme}://{self.host_port}"


def parse_target(raw: str) -> TargetSpec:
    """Parse a target given as a host, host:port, or full URL.

    The scheme is taken from the input when present; otherwise it is guessed
    from the port (well-known HTTP ports default to http, everything else to
    https).
    """
    text = raw.strip()
    scheme = ""
    if "://" in text:
        scheme, _, text = text.partition("://")
    text = text.split("/", 1)[0]
    host, port = _split_host_port(text)
    resolved_scheme = scheme.lower() or ("http" if port in _HTTP_PORTS else "https")
    return TargetSpec(scheme=resolved_scheme, host=host, port=port)


def _split_host_port(text: str) -> tuple[str, int | None]:
    if _looks_like_ipv6(text):
        return text, None
    if ":" not in text:
        return text.rstrip(".").lower(), None
    host, _, port_text = text.rpartition(":")
    if port_text.isdigit():
        return host.rstrip(".").lower(), int(port_text)
    return text.rstrip(".").lower(), None


@dataclass(frozen=True, slots=True)
class Scope:
    """An immutable set of scope rules (domains, wildcards, IPs, or CIDRs)."""

    rules: tuple[str, ...]

    @classmethod
    def empty(cls) -> Scope:
        """Return a scope that matches nothing."""
        return cls(())

    @classmethod
    def from_file(cls, path: str | Path) -> Scope:
        """Parse a scope file: one domain, wildcard, IP, or CIDR per line."""
        source = Path(path)
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise ScopeError(f"cannot read scope file {source}: {exc}") from exc
        rules = _parse_rules(text)
        if not rules:
            raise ScopeError(f"scope file {source} contains no usable rules")
        return cls(tuple(rules))

    def in_scope(self, host: str) -> bool:
        """Return whether `host` (a hostname, URL, or IP) is in scope."""
        normalized = normalize_host(host)
        if not normalized:
            return False
        return any(_rule_matches(rule, normalized) for rule in self.rules)

    def is_empty(self) -> bool:
        """Return whether the scope has no rules."""
        return not self.rules


def build_scope(target: str, scope_file: str | None = None) -> Scope:
    """Compose the effective scope: the explicit file rules plus the target."""
    base = normalize_host(target)
    if scope_file:
        file_scope = Scope.from_file(scope_file)
        return Scope((*file_scope.rules, base))
    return Scope((base,))


def normalize_host(value: str) -> str:
    """Reduce a URL, host:port, or hostname to a bare lowercase hostname."""
    text = value.strip().lower()
    if not text:
        return ""
    if "://" in text:
        text = urlsplit(text).hostname or ""
    elif "/" in text and not _looks_like_cidr(text):
        text = text.split("/", 1)[0]
    if ":" in text and not _looks_like_ipv6(text):
        text = text.split(":", 1)[0]
    return text.rstrip(".")


def _parse_rules(text: str) -> list[str]:
    rules: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(COMMENT_PREFIXES):
            continue
        normalized = normalize_host(line) if "://" in line else line
        candidate = normalized.lstrip("*.").rstrip(".").lower() if normalized.startswith("*.") else normalized.rstrip(".").lower()
        if not candidate:
            continue
        if line.startswith("*.") and not candidate.startswith("*."):
            candidate = f"*.{candidate}"
        rules.append(candidate)
    return rules


def _rule_matches(rule: str, host: str) -> bool:
    if _looks_like_cidr(rule):
        return _ip_in_network(host, rule)
    bare = rule.removeprefix("*.")
    return host == bare or host.endswith(f".{bare}")


def _ip_in_network(host: str, cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(host) in network
    except ValueError:
        return False


def _looks_like_cidr(text: str) -> bool:
    return "/" in text


def _looks_like_ipv6(text: str) -> bool:
    return text.count(":") >= 2
