"""Unit tests for the reflected-input context classifier."""

from __future__ import annotations

import pytest

from shaidra.stages.webvuln import _EXEC_CONTEXTS, _reflection_context

_MARKER = "sdrq<u>z9</u>k"


@pytest.mark.parametrize(
    ("html", "expected"),
    [
        (f"<html><body>{_MARKER}</body></html>", "html"),
        (f'<input name="q" value="{_MARKER}">', "attribute"),
        (f"<script>var x = '{_MARKER}';</script>", "script"),
        (f"<!-- {_MARKER} -->", "comment"),
        (f"<textarea>{_MARKER}</textarea>", "rawtext"),
        (f"<title>{_MARKER}</title>", "rawtext"),
    ],
)
def test_reflection_context_classifies_position(html: str, expected: str) -> None:
    assert _reflection_context(html, _MARKER) == expected


def test_reflection_context_returns_none_when_marker_absent() -> None:
    assert _reflection_context("<html><body>clean</body></html>", _MARKER) == "none"


def test_only_html_and_attribute_contexts_are_executable() -> None:
    assert _EXEC_CONTEXTS == frozenset({"html", "attribute"})
    assert "script" not in _EXEC_CONTEXTS
    assert "comment" not in _EXEC_CONTEXTS
