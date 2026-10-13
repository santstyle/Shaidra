"""Configuration loading with layered overrides.

Resolution order (first hit wins): an explicit path, $SHAIDRA_CONFIG, a
./config.yaml in the working directory, then the config.yaml shipped with the
package. Missing or malformed keys fall back to the built-in defaults, so the
tool always runs even without any config file present.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import yaml

from shaidra.core.models import JsonValue

DEFAULT_RATE_LIMIT: Final[int] = 40
DEFAULT_FILE_LIMIT: Final[int] = 0
DEFAULT_TIMEOUTS: Final[dict[str, int]] = {
    "subfinder": 300,
    "assetfinder": 300,
    "httpx": 300,
    "naabu": 600,
    "katana": 600,
    "nuclei": 900,
    "dalfox": 600,
    "sqlmap": 900,
    "ffuf": 900,
    "feroxbuster": 900,
    "wpscan": 900,
    "trufflehog": 600,
    "testssl": 600,
    "kiterunner": 600,
    "gowitness": 600,
}


@dataclass(frozen=True, slots=True)
class Config:
    """Resolved run configuration."""

    rate_limit: int = DEFAULT_RATE_LIMIT
    mode: str = "quick"
    reports_dir: str = "reports"
    wordlist_content: str = "wordlists/common.txt"
    wordlist_api: str = "wordlists/api.txt"
    ffuf_threads: int = 40
    katana_depth: int = 3
    waf_rate_limit_drop: float = 0.5
    timeouts: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_TIMEOUTS))

    def timeout_for(self, tool: str, default: int = 300) -> int:
        """Return the configured timeout for a tool, or `default`."""
        return self.timeouts.get(tool, default)

    def lowered_rate(self) -> int:
        """Return the rate limit to use when a WAF was detected."""
        return max(1, int(self.rate_limit * self.waf_rate_limit_drop))


def load_config(explicit: str | Path | None = None) -> Config:
    """Load configuration from the first available source, applying defaults."""
    path = resolve_config_path(explicit)
    data = read_config_mapping(path) if path is not None else {}
    return build_config(data)


def resolve_config_path(explicit: str | Path | None = None) -> Path | None:
    """Return the config file that would be used, or None if none exists."""
    if explicit is not None:
        return Path(explicit)
    env = os.environ.get("SHAIDRA_CONFIG")
    if env:
        return Path(env)
    local = Path.cwd() / "config.yaml"
    if local.is_file():
        return local
    packaged = Path(__file__).resolve().parents[1] / "config.yaml"
    if packaged.is_file():
        return packaged
    return None


def read_config_mapping(path: Path) -> dict[str, JsonValue]:
    """Read a YAML file into a typed mapping, returning {} on failure."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError:
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(key): value for key, value in raw.items()}


def build_config(data: Mapping[str, JsonValue]) -> Config:
    """Build a Config from a raw mapping, coercing each field defensively."""
    defaults = Config()
    wordlists = _as_mapping(data.get("wordlists"))
    return Config(
        rate_limit=_as_int(data.get("rate_limit"), defaults.rate_limit),
        mode=_as_str(data.get("mode"), defaults.mode),
        reports_dir=_as_str(data.get("reports_dir"), defaults.reports_dir),
        wordlist_content=_as_str(wordlists.get("content"), defaults.wordlist_content),
        wordlist_api=_as_str(wordlists.get("api"), defaults.wordlist_api),
        ffuf_threads=_as_int(data.get("ffuf_threads"), defaults.ffuf_threads),
        katana_depth=_as_int(data.get("katana_depth"), defaults.katana_depth),
        waf_rate_limit_drop=_as_float(data.get("waf_rate_limit_drop"), defaults.waf_rate_limit_drop),
        timeouts=_as_timeouts(data.get("timeouts")),
    )


def _as_mapping(value: JsonValue | None) -> Mapping[str, JsonValue]:
    if isinstance(value, dict):
        return value
    return {}


def _as_int(value: JsonValue | None, default: int) -> int:
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _as_float(value: JsonValue | None, default: float) -> float:
    if isinstance(value, bool) or value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _as_str(value: JsonValue | None, default: str) -> str:
    if isinstance(value, str) and value:
        return value
    return default


def _as_timeouts(value: JsonValue | None) -> dict[str, int]:
    result = dict(DEFAULT_TIMEOUTS)
    for key, raw in _as_mapping(value).items():
        coerced = _as_int(raw, -1)
        if coerced > 0:
            result[key] = coerced
    return result
