"""Credential and secret detection for response bodies.

A small regex rule engine tuned for precision over recall: each rule targets a
well-known token shape (AWS keys, Stripe keys, private-key headers, database
URIs, ...) or a high-entropy value assigned to a credential-like key. Generic
assignment rules are gated behind a Shannon-entropy check and a placeholder
filter so configuration such as ``api_key=changeme`` never produces a finding.

Matches are redacted before they leave this module: a leaked secret is never
carried verbatim into a finding, a report, or the terminal.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Final

from shaidra.core.models import Severity

#: Upper bound on matches returned per body, so one noisy page cannot flood a report.
MAX_MATCHES: Final[int] = 50

#: Shannon-entropy floor for generic assignment rules (bits per character).
_ENTROPY_FLOOR: Final[float] = 3.0

#: Generic values must also be at least this long to be considered a secret.
_GENERIC_MIN_LEN: Final[int] = 16

#: Substrings that mark an obvious placeholder rather than a real credential.
_PLACEHOLDER_HINTS: Final[tuple[str, ...]] = (
    "example", "placeholder", "changeme", "change_me", "your_", "yourapi", "yourtoken",
    "xxxx", "dummy", "sample", "redacted", "fixme", "todo", "lorem", "foobar",
    "insert", "replace", "here", "<", ">", "${", "{{", "%s", "null", "undefined",
)


@dataclass(frozen=True, slots=True)
class SecretMatch:
    """One confirmed secret occurrence, already redacted for safe reporting."""

    rule: str
    severity: Severity
    description: str
    redacted: str
    reference: str | None = None


@dataclass(frozen=True, slots=True)
class _Rule:
    """A single detection rule: a named pattern plus its reporting metadata."""

    name: str
    severity: Severity
    pattern: re.Pattern[str]
    description: str
    reference: str | None = None
    group: int = 0
    entropy_checked: bool = False
    luhn_checked: bool = False


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


# Rules are ordered from the most specific/dangerous to the most generic.
_RULES: Final[tuple[_Rule, ...]] = (
    _Rule(
        "Private key block", Severity.CRITICAL,
        _compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        "A PEM private key is embedded in the response.",
        "https://cwe.mitre.org/data/definitions/798.html",
    ),
    _Rule(
        "Stripe live secret key", Severity.CRITICAL,
        _compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
        "A Stripe live secret key is exposed.",
    ),
    _Rule(
        "AWS access key id", Severity.HIGH,
        _compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b"),
        "An AWS access key id is exposed.",
        "https://cwe.mitre.org/data/definitions/798.html",
    ),
    _Rule(
        "AWS secret access key", Severity.HIGH,
        _compile(r"(?i)aws[^\n]{0,40}?(?:secret|access)[^\n]{0,20}?['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "A 40-character AWS secret access key appears next to an AWS label.",
        group=1, entropy_checked=True,
    ),
    _Rule(
        "Google API key", Severity.HIGH,
        _compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "A Google API key is exposed.",
    ),
    _Rule(
        "Google OAuth client secret", Severity.HIGH,
        _compile(r"\bGOCSPX-[0-9A-Za-z\-_]{28,}\b"),
        "A Google OAuth client secret is exposed.",
    ),
    _Rule(
        "OpenAI API key", Severity.HIGH,
        _compile(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b"),
        "An OpenAI API key is exposed.",
    ),
    _Rule(
        "Anthropic API key", Severity.HIGH,
        _compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"),
        "An Anthropic API key is exposed.",
    ),
    _Rule(
        "GitHub token", Severity.HIGH,
        _compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
        "A GitHub personal access token is exposed.",
    ),
    _Rule(
        "GitHub fine-grained token", Severity.HIGH,
        _compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
        "A GitHub fine-grained token is exposed.",
    ),
    _Rule(
        "GitLab personal access token", Severity.HIGH,
        _compile(r"\bglpat-[A-Za-z0-9\-_]{20}\b"),
        "A GitLab personal access token is exposed.",
    ),
    _Rule(
        "Slack token", Severity.HIGH,
        _compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        "A Slack API token is exposed.",
    ),
    _Rule(
        "SendGrid API key", Severity.HIGH,
        _compile(r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b"),
        "A SendGrid API key is exposed.",
    ),
    _Rule(
        "Shopify access token", Severity.HIGH,
        _compile(r"\bshpat_[a-fA-F0-9]{32}\b"),
        "A Shopify access token is exposed.",
    ),
    _Rule(
        "npm access token", Severity.HIGH,
        _compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "An npm access token is exposed.",
    ),
    _Rule(
        "PyPI upload token", Severity.HIGH,
        _compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b"),
        "A PyPI upload token is exposed.",
    ),
    _Rule(
        "Facebook access token", Severity.HIGH,
        _compile(r"\bEAACEdEose0cBA[0-9A-Za-z]+\b"),
        "A Facebook access token is exposed.",
    ),
    _Rule(
        "Azure storage account key", Severity.HIGH,
        _compile(r"(?i)AccountKey=[A-Za-z0-9+/=]{40,}"),
        "An Azure storage account key is exposed.",
    ),
    _Rule(
        "Google service account JSON", Severity.HIGH,
        _compile(r'"type"\s*:\s*"service_account"'),
        "A Google service-account JSON document is embedded in the response.",
    ),
    _Rule(
        "Database URI with credentials", Severity.HIGH,
        _compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:@\s/]+:[^@\s/]+@[^\s\"'<>]+"),
        "A database connection string with an embedded username and password is exposed.",
    ),
    _Rule(
        "Stripe restricted key", Severity.HIGH,
        _compile(r"\brk_live_[0-9a-zA-Z]{24,}\b"),
        "A Stripe restricted live key is exposed.",
    ),
    _Rule(
        "JSON Web Token", Severity.MEDIUM,
        _compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "A JSON Web Token is embedded in the response.",
    ),
    _Rule(
        "Twilio account sid", Severity.MEDIUM,
        _compile(r"\bAC[0-9a-fA-F]{32}\b"),
        "A Twilio account SID is exposed.",
    ),
    _Rule(
        "Mailgun API key", Severity.MEDIUM,
        _compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
        "A Mailgun API key is exposed.",
    ),
    _Rule(
        "Mailchimp API key", Severity.MEDIUM,
        _compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"),
        "A Mailchimp API key is exposed.",
    ),
    _Rule(
        "Telegram bot token", Severity.MEDIUM,
        _compile(r"\b[0-9]{8,10}:AA[A-Za-z0-9\-_]{33}\b"),
        "A Telegram bot token is exposed.",
    ),
    _Rule(
        "Slack incoming webhook", Severity.MEDIUM,
        _compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z_]+"),
        "A Slack incoming-webhook URL is exposed.",
    ),
    _Rule(
        "Discord webhook", Severity.MEDIUM,
        _compile(r"https://(?:canary\.|ptb\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+"),
        "A Discord webhook URL is exposed.",
    ),
    _Rule(
        "URL with embedded credentials", Severity.MEDIUM,
        _compile(r"(?i)\bhttps?://[^:@\s/]+:[^@\s/]+@[^\s\"'<>]+"),
        "A URL embeds a username and password in cleartext.",
    ),
    _Rule(
        "Firebase database URL", Severity.LOW,
        _compile(r"https://[a-z0-9-]+\.firebaseio\.com\b"),
        "A Firebase Realtime Database URL is exposed.",
    ),
    _Rule(
        "US Social Security Number", Severity.MEDIUM,
        _compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"),
        "A US Social Security Number is exposed.",
        "https://cwe.mitre.org/data/definitions/359.html",
    ),
    _Rule(
        "Credit card number", Severity.HIGH,
        _compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"),
        "A payment card number is exposed.",
        "https://cwe.mitre.org/data/definitions/359.html",
        luhn_checked=True,
    ),
    _Rule(
        "Inline credential assignment", Severity.MEDIUM,
        _compile(
            r"(?i)(?:[A-Za-z0-9_.\-]*"
            r"(?:password|passwd|pwd|secret|token|apikey|api[_-]?key|access[_-]?key|"
            r"private[_-]?key|credential)"
            r"[A-Za-z0-9_.\-]*)"
            r"\s*['\"]?\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]"
        ),
        "A credential-like key is assigned a high-entropy literal value.",
        group=1, entropy_checked=True,
    ),
    _Rule(
        "Env-style credential assignment", Severity.MEDIUM,
        _compile(
            r"(?im)^\s*[A-Z][A-Z0-9_]*"
            r"(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL)"
            r"[A-Z0-9_]*\s*=\s*(\S{16,})\s*$"
        ),
        "A .env-style variable holds a high-entropy credential value.",
        group=1, entropy_checked=True,
    ),
)


def scan_text(text: str) -> list[SecretMatch]:
    """Return every distinct secret found in ``text``, redacted and deduplicated."""
    matches: list[SecretMatch] = []
    seen: set[tuple[str, str]] = set()
    for rule in _RULES:
        for occurrence in rule.pattern.finditer(text):
            value = occurrence.group(rule.group)
            if not _plausible(value, rule):
                continue
            redacted = _redact(value)
            key = (rule.name, redacted)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                SecretMatch(
                    rule=rule.name,
                    severity=rule.severity,
                    description=rule.description,
                    redacted=redacted,
                    reference=rule.reference,
                )
            )
            if len(matches) >= MAX_MATCHES:
                return matches
    return matches


def _plausible(value: str, rule: _Rule) -> bool:
    """Reject placeholder or low-entropy values that only look like secrets."""
    stripped = value.strip()
    if len(stripped) < 6:
        return False
    lowered = stripped.lower()
    if any(hint in lowered for hint in _PLACEHOLDER_HINTS):
        return False
    if rule.entropy_checked:
        if len(stripped) < _GENERIC_MIN_LEN:
            return False
        if _entropy(stripped) < _ENTROPY_FLOOR:
            return False
    return not rule.luhn_checked or _luhn(stripped)


def _luhn(value: str) -> bool:
    """Return True when ``value`` is a Luhn-valid card-like number."""
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _entropy(value: str) -> float:
    """Shannon entropy in bits per character for ``value``."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _redact(value: str) -> str:
    """Mask the middle of a secret, keeping only enough to recognize it."""
    stripped = value.strip()
    if len(stripped) <= 8:
        return stripped[:2] + "*" * max(0, len(stripped) - 2)
    return f"{stripped[:4]}{'*' * 8}{stripped[-4:]}"
