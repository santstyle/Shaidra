"""Tests for layered configuration loading.

Covers resolution order (explicit path > $SHAIDRA_CONFIG > ./config.yaml >
packaged config), defensive coercion of malformed values back to defaults,
and the WAF rate-drop arithmetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shaidra.core.config import (
    DEFAULT_RATE_LIMIT,
    DEFAULT_TIMEOUTS,
    Config,
    build_config,
    load_config,
    read_config_mapping,
    resolve_config_path,
)


class TestConfigAccessors:
    def test_timeout_for_known_tool(self) -> None:
        assert Config().timeout_for("nuclei") == DEFAULT_TIMEOUTS["nuclei"]

    def test_timeout_for_unknown_tool_uses_default(self) -> None:
        assert Config().timeout_for("nope") == 300
        assert Config().timeout_for("nope", 42) == 42

    def test_lowered_rate_halves_budget(self) -> None:
        assert Config(rate_limit=40, waf_rate_limit_drop=0.5).lowered_rate() == 20

    def test_lowered_rate_never_drops_below_one(self) -> None:
        assert Config(rate_limit=1, waf_rate_limit_drop=0.5).lowered_rate() == 1
        assert Config(rate_limit=3, waf_rate_limit_drop=0.1).lowered_rate() == 1


class TestResolveConfigPath:
    def test_explicit_path_wins(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        explicit = tmp_path / "custom.yaml"
        monkeypatch.setenv("SHAIDRA_CONFIG", str(tmp_path / "env.yaml"))
        assert resolve_config_path(explicit) == explicit

    def test_env_var_used_when_no_explicit_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        env_path = tmp_path / "env.yaml"
        monkeypatch.setenv("SHAIDRA_CONFIG", str(env_path))
        assert resolve_config_path(None) == env_path

    def test_local_config_beats_packaged(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SHAIDRA_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)
        (tmp_path / "config.yaml").write_text("rate_limit: 5\n", encoding="utf-8")
        assert resolve_config_path(None) == tmp_path / "config.yaml"

    def test_falls_back_to_packaged_config(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SHAIDRA_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)
        resolved = resolve_config_path(None)
        assert resolved is not None
        assert resolved.name == "config.yaml"

    def test_returns_none_when_nothing_exists(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SHAIDRA_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)
        packaged = Path(__file__).resolve().parents[1] / "config.yaml"
        assert packaged.exists() or resolve_config_path(None) is None


class TestReadConfigMapping:
    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert read_config_mapping(tmp_path / "absent.yaml") == {}

    def test_invalid_yaml_returns_empty(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("key: [unclosed\n  : : bad\n", encoding="utf-8")
        assert read_config_mapping(bad) == {}

    def test_non_mapping_yaml_returns_empty(self, tmp_path: Path) -> None:
        scalar = tmp_path / "scalar.yaml"
        scalar.write_text("- just\n- a\n- list\n", encoding="utf-8")
        assert read_config_mapping(scalar) == {}

    def test_valid_yaml_returns_string_keyed_mapping(self, tmp_path: Path) -> None:
        good = tmp_path / "good.yaml"
        good.write_text("rate_limit: 10\nmode: deep\n", encoding="utf-8")
        assert read_config_mapping(good) == {"rate_limit": 10, "mode": "deep"}


class TestBuildConfig:
    def test_empty_mapping_yields_defaults(self) -> None:
        config = build_config({})
        assert config == Config()

    def test_values_are_applied(self) -> None:
        config = build_config(
            {
                "rate_limit": 10,
                "mode": "deep",
                "reports_dir": "out",
                "ffuf_threads": 8,
                "katana_depth": 6,
                "waf_rate_limit_drop": 0.25,
                "oob_host": "callback.example",
                "wordlists": {"content": "wl/content.txt", "api": "wl/api.txt", "subdomains": "wl/subs.txt"},
                "timeouts": {"nuclei": 120},
            }
        )
        assert config.rate_limit == 10
        assert config.mode == "deep"
        assert config.reports_dir == "out"
        assert config.ffuf_threads == 8
        assert config.katana_depth == 6
        assert config.waf_rate_limit_drop == 0.25
        assert config.oob_host == "callback.example"
        assert config.wordlist_content == "wl/content.txt"
        assert config.wordlist_api == "wl/api.txt"
        assert config.wordlist_subdomains == "wl/subs.txt"
        assert config.timeouts["nuclei"] == 120
        assert config.timeouts["ffuf"] == DEFAULT_TIMEOUTS["ffuf"]

    @pytest.mark.parametrize(
        ("bad", "fallback"),
        [
            (True, DEFAULT_RATE_LIMIT),
            (None, DEFAULT_RATE_LIMIT),
            ("not-a-number", DEFAULT_RATE_LIMIT),
            ([1, 2], DEFAULT_RATE_LIMIT),
            ({}, DEFAULT_RATE_LIMIT),
        ],
    )
    def test_bad_rate_limit_falls_back_to_default(self, bad: object, fallback: int) -> None:
        assert build_config({"rate_limit": bad}).rate_limit == fallback

    def test_numeric_coercions(self) -> None:
        assert build_config({"rate_limit": "80"}).rate_limit == 80
        assert build_config({"rate_limit": 3.9}).rate_limit == 3
        assert build_config({"waf_rate_limit_drop": "0.2"}).waf_rate_limit_drop == pytest.approx(0.2)
        assert build_config({"waf_rate_limit_drop": 1}).waf_rate_limit_drop == 1.0

    def test_bad_float_and_bool_drop_fall_back(self) -> None:
        assert build_config({"waf_rate_limit_drop": "abc"}).waf_rate_limit_drop == 0.5
        assert build_config({"waf_rate_limit_drop": True}).waf_rate_limit_drop == 0.5

    @pytest.mark.parametrize("bad", ["", None, 42, []])
    def test_non_string_mode_falls_back(self, bad: object) -> None:
        assert build_config({"mode": bad}).mode == "quick"

    def test_blank_oob_host_is_none(self) -> None:
        assert build_config({"oob_host": "   "}).oob_host is None
        assert build_config({"oob_host": " cb.example "}).oob_host == "cb.example"

    def test_non_mapping_wordlists_use_defaults(self) -> None:
        defaults = Config()
        config = build_config({"wordlists": "not-a-mapping"})
        assert config.wordlist_content == defaults.wordlist_content

    @pytest.mark.parametrize("bad", [True, None, 0, -5, "nope"])
    def test_invalid_timeout_keeps_default(self, bad: object) -> None:
        config = build_config({"timeouts": {"nuclei": bad}})
        assert config.timeouts["nuclei"] == DEFAULT_TIMEOUTS["nuclei"]

    def test_valid_timeout_overrides(self) -> None:
        assert build_config({"timeouts": {"nuclei": "42"}}).timeouts["nuclei"] == 42


class TestLoadConfig:
    def test_explicit_file_is_loaded(self, tmp_path: Path) -> None:
        cfg = tmp_path / "run.yaml"
        cfg.write_text("rate_limit: 7\n", encoding="utf-8")
        assert load_config(cfg).rate_limit == 7

    def test_unreadable_explicit_file_yields_defaults(self, tmp_path: Path) -> None:
        assert load_config(tmp_path / "absent.yaml").rate_limit == DEFAULT_RATE_LIMIT
