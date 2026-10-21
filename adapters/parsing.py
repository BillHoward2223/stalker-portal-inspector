"""Shared response helpers for the documented adapter."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from models.errors import InvalidInputError

_PLACEHOLDER = re.compile(r"\{([^{}]+)\}")


def dig(payload: Any, path: str | None) -> Any:
    """Walk a dotted path through dictionaries. Missing keys return None."""

    if path is None:
        return None
    current = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def as_text(value: Any) -> str | None:
    """Convert a scalar API value to text. Objects and lists are treated as unavailable."""

    if value is None or isinstance(value, (dict, list)):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip()
    if not text:
        return None
    return text[:500]


def apply_placeholders(template: str, values: dict[str, str], *, encode: bool) -> str:
    """Substitute {mac} and {serial}. Any other placeholder is rejected."""

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in {"mac", "serial"}:
            raise InvalidInputError("The API specification contains an unsupported placeholder.")
        if name not in values:
            raise InvalidInputError("This endpoint requires a device serial number.")
        if encode:
            return quote(values[name], safe="")
        return values[name]

    if "{" not in template and "}" not in template:
        return template
    applied = _PLACEHOLDER.sub(replace, template)
    if "{" in applied or "}" in applied:
        raise InvalidInputError("The API specification contains an unsupported placeholder.")
    return applied
