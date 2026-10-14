"""Tests for CMS/version fingerprint extraction (generator meta, WhatWeb)."""

from __future__ import annotations

from shaidra.stages.fingerprint import _find_generator, _whatweb_version


def test_find_generator_handles_either_attribute_order() -> None:
    assert _find_generator('<meta name="generator" content="WordPress 5.8">') == "wordpress 5.8"
    assert (
        _find_generator('<meta content="Drupal 7 (http://drupal.org)" name="generator">')
        == "drupal 7 (http://drupal.org)"
    )


def test_find_generator_returns_none_without_a_generator_tag() -> None:
    assert _find_generator('<meta name="viewport" content="width=device-width">') is None
    assert _find_generator("<html><head></head></html>") is None


def test_whatweb_version_reads_dict_and_list_shapes() -> None:
    assert _whatweb_version({"version": ["2.4.49"], "string": ["Apache"]}) == "2.4.49"
    assert _whatweb_version([{"version": ["1.12.4"]}]) == "1.12.4"
    assert _whatweb_version({"version": "1.12.4"}) == "1.12.4"


def test_whatweb_version_returns_none_without_a_version() -> None:
    assert _whatweb_version({"string": ["Apache"]}) is None
    assert _whatweb_version(None) is None
