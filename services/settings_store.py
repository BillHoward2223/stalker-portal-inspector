"""Persist non-secret connection settings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SettingsStore:
    """JSON settings restricted to connection fields. Credentials are dropped."""

    allowed_keys = frozenset(
        {"portal_url", "auth_method", "mac_address", "serial_number", "timeout_seconds", "spec_path"}
    )

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {}
        if not isinstance(data, dict):
            return {}
        return {key: value for key, value in data.items() if self._accepted(key, value)}

    def save(self, values: dict[str, Any]) -> None:
        safe = {key: value for key, value in values.items() if self._accepted(key, value)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(safe, indent=2) + "\n", encoding="utf-8")
        temporary.replace(self.path)

    def _accepted(self, key: Any, value: Any) -> bool:
        if key not in self.allowed_keys or isinstance(value, bool):
            return False
        return isinstance(value, (str, int, float))
