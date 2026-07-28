"""Tests for the robust JSON extraction helpers."""

from __future__ import annotations

import pytest

from redteam.agents._parsing import parse_json_array, parse_json_object


def test_parse_plain_object():
    assert parse_json_object('{"a": 1}') == {"a": 1}


def test_parse_object_in_fence():
    text = 'Here you go:\n```json\n{"score": "pass"}\n```\nHope that helps!'
    assert parse_json_object(text) == {"score": "pass"}


def test_parse_object_with_surrounding_prose():
    text = 'The verdict is {"score": "high", "note": "has } brace"} — done.'
    obj = parse_json_object(text)
    assert obj["score"] == "high"
    # The closing brace inside the string value must not truncate parsing.
    assert obj["note"] == "has } brace"


def test_parse_array_with_prose():
    text = 'prompts: [ {"variant": 1, "prompt": "hi"} ] end'
    arr = parse_json_array(text)
    assert arr[0]["variant"] == 1


def test_parse_failure_raises():
    with pytest.raises(ValueError):
        parse_json_object("no json here at all")