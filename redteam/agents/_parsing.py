"""Robust JSON extraction from LLM output.

Models sometimes wrap JSON in prose or ```json fences despite instructions.
These helpers extract the first valid JSON value of the expected shape so a
single formatting quirk doesn't crash a whole campaign.
"""

from __future__ import annotations

import json
import re
from typing import Any

# Matches a fenced ```json ... ``` (or plain ``` ... ```) block.
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def _strip_fences(text: str) -> str:
    match = _FENCE_RE.search(text)
    return match.group(1).strip() if match else text.strip()


def _extract_balanced(text: str, open_ch: str, close_ch: str) -> str | None:
    """Return the first balanced ``open_ch..close_ch`` span in ``text``.

    Handles nested brackets and ignores brackets inside double-quoted strings so
    that, e.g., a ``}`` inside a JSON string value does not terminate the object
    early.
    """
    start = text.find(open_ch)
    if start == -1:
        return None
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def parse_json_object(text: str) -> dict[str, Any]:
    """Parse the first JSON object found in ``text``.

    Raises:
        ValueError: if no valid JSON object can be extracted.
    """
    cleaned = _strip_fences(text)
    try:
        value = json.loads(cleaned)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass
    span = _extract_balanced(cleaned, "{", "}")
    if span is not None:
        try:
            value = json.loads(span)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            pass
    raise ValueError(f"Could not parse a JSON object from model output: {text[:200]!r}")


def parse_json_array(text: str) -> list[Any]:
    """Parse the first JSON array found in ``text``.

    Raises:
        ValueError: if no valid JSON array can be extracted.
    """
    cleaned = _strip_fences(text)
    try:
        value = json.loads(cleaned)
        if isinstance(value, list):
            return value
    except json.JSONDecodeError:
        pass
    span = _extract_balanced(cleaned, "[", "]")
    if span is not None:
        try:
            value = json.loads(span)
            if isinstance(value, list):
                return value
        except json.JSONDecodeError:
            pass
    raise ValueError(f"Could not parse a JSON array from model output: {text[:200]!r}")