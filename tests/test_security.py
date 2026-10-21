"""Credential storage, settings files, and export redaction."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from models.errors import CredentialStoreError
from security.credentials import KeyringCredentialStore, MemoryCredentialStore
from security.redaction import RedactingFormatter, redact_data, redact_text
from services.settings_store import SettingsStore


def test_redaction_removes_secrets_and_keeps_the_session_timestamp() -> None:
    payload = {
        "status": "active",
        "password": "synthetic-password",
        "nested": {"access_token": "synthetic-access-token", "session_connected_at": "2026-10-22T05:10:00+00:00"},
        "note": "Authorization: Bearer synthetic-access-token",
    }
    redacted = redact_data(payload)
    assert redacted["status"] == "active"
    assert redacted["password"] == "[REDACTED]"
    assert redacted["nested"]["access_token"] == "[REDACTED]"
    assert redacted["nested"]["session_connected_at"] == "2026-10-22T05:10:00+00:00"
    assert "synthetic-access-token" not in redacted["note"]
    assert "synthetic-password" not in redact_text("password=synthetic-password")


def test_log_formatter_redacts_bearer_tokens() -> None:
    formatter = RedactingFormatter("%(message)s")
    record = logging.LogRecord(
        "test",
        logging.INFO,
        __file__,
        1,
        "Authorization Bearer synthetic-access-token",
        (),
        None,
    )
    rendered = formatter.format(record)
    assert "synthetic-access-token" not in rendered
    assert "[REDACTED]" in rendered


def test_settings_store_drops_secrets(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path / "settings.json")
    store.save(
        {
            "portal_url": "https://portal.example.com",
            "auth_method": "documented_api",
            "mac_address": "00:1A:79:00:00:01",
            "timeout_seconds": 15,
            "password": "synthetic-password",
            "api_key": "synthetic-key",
        }
    )
    written = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert "password" not in written
    assert "api_key" not in written
    assert store.load()["portal_url"] == "https://portal.example.com"


def test_memory_credential_store_round_trip() -> None:
    store = MemoryCredentialStore()
    store.set_secret("portal.example.com", "password", "synthetic-password")
    assert store.get_secret("PORTAL.EXAMPLE.COM", "password") == "synthetic-password"
    store.delete_secret("portal.example.com", "password")
    assert store.get_secret("portal.example.com", "password") is None
    with pytest.raises(CredentialStoreError):
        store.set_secret("portal.example.com", "password", "")
    with pytest.raises(CredentialStoreError):
        store.set_secret("portal.example.com", "handshake", "value")


class _FakeKeyring:
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, item: str) -> str | None:
        return self.items.get((service, item))

    def set_password(self, service: str, item: str, value: str) -> None:
        self.items[(service, item)] = value

    def delete_password(self, service: str, item: str) -> None:
        self.items.pop((service, item), None)


def test_keyring_store_uses_the_application_service_name() -> None:
    backend = _FakeKeyring()
    store = KeyringCredentialStore(backend)
    store.set_secret("portal.example.com", "bearer_token", "synthetic-bearer-token")
    assert store.get_secret("portal.example.com", "bearer_token") == "synthetic-bearer-token"
    assert ("StalkerPortalInspector", "portal.example.com:bearer_token") in backend.items
    store.delete_secret("portal.example.com", "bearer_token")
    assert store.get_secret("portal.example.com", "bearer_token") is None
