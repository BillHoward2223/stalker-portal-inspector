"""Redact secrets from logs and exported reports."""

from __future__ import annotations

import logging
import re
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_PARTS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "bearer",
    }
)

_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{6,}")
_BASIC = re.compile(r"(?i)\b(basic\s+)[A-Za-z0-9+/=]{8,}")
_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization|cookie|session)"
    r"\b(\s*[=:]\s*)(\S+)"
)


def is_sensitive_key(key: str) -> bool:
    """Return whether a JSON key should be removed from an export or log."""

    folded = key.lower().replace("-", "_")
    if folded == "session_connected_at":
        return False
    parts = set(folded.split("_"))
    if parts & _SENSITIVE_PARTS:
        return True
    if {"api", "key"} <= parts:
        return True
    return "session" in parts


def redact_text(value: str) -> str:
    """Remove credential-shaped text while leaving ordinary status messages intact."""

    redacted = _BEARER.sub(rf"\1{REDACTED}", value)
    redacted = _BASIC.sub(rf"\1{REDACTED}", redacted)
    return _ASSIGNMENT.sub(lambda match: match.group(1) + match.group(2) + REDACTED, redacted)


def redact_data(value: Any) -> Any:
    """Return a copy of JSON-like data with sensitive keys replaced."""

    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            text = str(key)
            redacted[text] = REDACTED if is_sensitive_key(text) else redact_data(item)
        return redacted
    if isinstance(value, list):
        return [redact_data(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class RedactingFormatter(logging.Formatter):
    """Format a log record, then scrub credential-shaped text from the result."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record))
