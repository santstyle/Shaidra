"""Tests for the credential/secret detection engine.

Covers the public scanner (redaction, dedup, match cap) and the private
helpers (Luhn check, Shannon entropy, redaction format) that gate precision.
"""

from __future__ import annotations

import pytest

from shaidra.core.models import Severity
from shaidra.utils.secrets import MAX_MATCHES, SecretMatch, _entropy, _luhn, _plausible, _redact, scan_text


class TestScanText:
    def test_empty_text_has_no_matches(self) -> None:
        assert scan_text("") == []

    def test_clean_text_has_no_matches(self) -> None:
        assert scan_text("just a normal page with api_key=short and password=hunter2") == []

    def test_private_key_block_detected(self) -> None:
        text = "config dump follows:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...\n"
        matches = scan_text(text)
        assert [m.rule for m in matches] == ["Private key block"]
        assert matches[0].severity is Severity.CRITICAL

    def test_stripe_live_key_detected_and_redacted(self) -> None:
        key = "sk_live_" + "a1b2c3d4" * 3  # 24+ chars after the prefix
        matches = scan_text(f"stripe: {key}")
        assert matches
        assert matches[0].rule == "Stripe live secret key"
        assert key not in matches[0].redacted
        assert matches[0].redacted.startswith("sk_l")

    def test_aws_access_key_id_detected(self) -> None:
        key = "AKIA" + "ABCDEFGHIJKLMNOP"
        matches = scan_text(f"aws_key_id = {key}")
        assert any(m.rule == "AWS access key id" for m in matches)

    def test_aws_access_key_id_with_lowercase_prefix_ignored(self) -> None:
        assert scan_text("akia" + "ABCDEFGHIJKLMNOP") == []

    def test_placeholder_values_are_rejected(self) -> None:
        text = 'api_key = "changeme1234567890"\nSECRET_TOKEN=yourtoken1234567890\n'
        for match in scan_text(text):
            assert "changeme" not in match.redacted.lower()

    def test_low_entropy_generic_assignment_rejected(self) -> None:
        text = 'password = "aaaaaaaaaaaaaaaaaaaa"\n'
        assert scan_text(text) == []

    def test_duplicate_secrets_collapse_to_one_match(self) -> None:
        key = "sk_live_" + "f" * 24
        matches = scan_text(f"{key}\nand again {key}")
        stripe = [m for m in matches if m.rule == "Stripe live secret key"]
        assert len(stripe) == 1

    def test_match_list_is_capped(self) -> None:
        keys = "\n".join(f"AKIA{i:016d}" for i in range(MAX_MATCHES + 10))
        assert len(scan_text(keys)) == MAX_MATCHES

    def test_matches_are_secret_match_records(self) -> None:
        matches = scan_text("-----BEGIN PRIVATE KEY-----")
        assert all(isinstance(m, SecretMatch) for m in matches)
        assert all(m.description for m in matches)


class TestLuhn:
    def test_valid_visa_test_number(self) -> None:
        assert _luhn("4111111111111111") is True

    def test_invalid_checksum(self) -> None:
        assert _luhn("4111111111111112") is False

    def test_too_few_digits(self) -> None:
        assert _luhn("123456789012") is False

    def test_too_many_digits(self) -> None:
        assert _luhn("1" * 20) is False

    def test_non_digit_text_has_no_luhn_number(self) -> None:
        assert _luhn("not a card at all") is False


class TestEntropy:
    def test_empty_string_is_zero(self) -> None:
        assert _entropy("") == 0.0

    def test_uniform_string_has_zero_entropy(self) -> None:
        assert _entropy("aaaaaaaa") == 0.0

    def test_diverse_string_has_higher_entropy(self) -> None:
        assert _entropy("abcdefgh") > _entropy("aaaaabbb")


class TestRedact:
    def test_short_values_mask_all_but_prefix(self) -> None:
        assert _redact("abcdef") == "ab****"
        assert _redact("ab") == "ab"

    def test_long_values_keep_first_and_last_four(self) -> None:
        redacted = _redact("0123456789abcdefghij")
        assert redacted == "0123" + "*" * 8 + "ghij"

    def test_value_is_stripped_before_masking(self) -> None:
        assert _redact("  short12  ").startswith("sh")


class TestPlausible:
    def _rule(self, *, entropy_checked: bool = False, luhn_checked: bool = False):
        from shaidra.utils.secrets import _Rule

        return _Rule(
            name="t",
            severity=Severity.INFO,
            pattern=__import__("re").compile("x"),
            description="d",
            entropy_checked=entropy_checked,
            luhn_checked=luhn_checked,
        )

    def test_values_under_six_chars_rejected(self) -> None:
        assert _plausible("abc", self._rule()) is False

    def test_placeholder_hints_rejected(self) -> None:
        assert _plausible("your_api_key_value", self._rule()) is False
        assert _plausible("SAMPLE_VALUE_1234", self._rule()) is False

    def test_entropy_checked_rule_rejects_short_and_flat_values(self) -> None:
        rule = self._rule(entropy_checked=True)
        assert _plausible("abcdefghijklmno", rule) is False  # 15 chars < 16
        assert _plausible("a" * 40, rule) is False

    def test_entropy_checked_rule_accepts_high_entropy(self) -> None:
        assert _plausible("kR7xP2mQ9vL4nT8wY1zA", self._rule(entropy_checked=True)) is True

    def test_luhn_checked_rule_gates_on_checksum(self) -> None:
        rule = self._rule(luhn_checked=True)
        assert _plausible("4111111111111111", rule) is True
        assert _plausible("4111111111111112", rule) is False

    @pytest.mark.parametrize("hint", ["CHANGE_ME_value", "xxxx-secret-xxxx", "lorem ipsum"])
    def test_more_placeholder_hints(self, hint: str) -> None:
        assert _plausible(hint, self._rule()) is False
