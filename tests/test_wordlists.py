"""Sanity tests for the packaged wordlists and the built-in port list."""

from __future__ import annotations

from pathlib import Path

import pytest

from shaidra.stages.content_discovery import _resolve_wordlist, _wordlist_lines
from shaidra.stages.recon import _COMMON_PORTS

_WORDLIST_DIR = Path(__file__).resolve().parent.parent / "wordlists"


def _entries(name: str) -> list[str]:
    lines = (line.strip() for line in _wordlist_lines(_WORDLIST_DIR / name))
    return [line for line in lines if line and not line.startswith("#")]


@pytest.mark.parametrize("name", ["common.txt", "subdomains.txt", "api.txt"])
def test_wordlists_are_present_and_substantial(name: str) -> None:
    assert (_WORDLIST_DIR / name).is_file()
    assert len(_entries(name)) >= 50


@pytest.mark.parametrize("name", ["common.txt", "subdomains.txt", "api.txt"])
def test_wordlists_have_no_duplicate_entries(name: str) -> None:
    entries = _entries(name)
    assert len(entries) == len(set(entries))


def test_common_ports_are_sorted_unique_and_valid() -> None:
    assert len(_COMMON_PORTS) >= 100
    assert list(_COMMON_PORTS) == sorted(_COMMON_PORTS)
    assert len(set(_COMMON_PORTS)) == len(_COMMON_PORTS)
    assert all(0 < port < 65536 for port in _COMMON_PORTS)


def test_resolve_wordlist_falls_back_to_packaged_common() -> None:
    resolved = _resolve_wordlist("a-wordlist-that-does-not-exist.txt")
    assert resolved is not None
    assert resolved.name == "common.txt"
    assert resolved.is_file()
