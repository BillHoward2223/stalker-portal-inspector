"""Credential storage. Secrets are never written to the JSON settings file."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from models.errors import CredentialStoreError

SERVICE_NAME = "StalkerPortalInspector"
ALLOWED_SECRET_NAMES = frozenset({"username", "password", "api_key", "bearer_token"})
_MAX_SECRET_LENGTH = 8192


def _validate_secret(name: str, value: str) -> str:
    if name not in ALLOWED_SECRET_NAMES:
        raise CredentialStoreError("That credential type cannot be stored.")
    if not isinstance(value, str) or not value.strip():
        raise CredentialStoreError("Empty credentials cannot be stored.")
    if len(value) > _MAX_SECRET_LENGTH or any(ord(character) < 32 for character in value):
        raise CredentialStoreError("The credential value is not supported.")
    return value


@dataclass
class SecretBundle:
    """In-memory credentials for a single connection. Cleared on disconnect."""

    username: str | None = None
    password: str | None = None
    api_key: str | None = None
    bearer_token: str | None = None

    def clear(self) -> None:
        self.username = None
        self.password = None
        self.api_key = None
        self.bearer_token = None


class CredentialStore(Protocol):
    """Small store interface so tests can avoid the operating-system keyring."""

    def get_secret(self, host: str, name: str) -> str | None:
        """Return a stored secret, or None when it is absent."""

    def set_secret(self, host: str, name: str, value: str) -> None:
        """Store one secret for a portal host."""

    def delete_secret(self, host: str, name: str) -> None:
        """Remove one secret. Missing entries are ignored."""


class MemoryCredentialStore:
    """Process-local store used by tests and by a session that opts out of saving."""

    def __init__(self) -> None:
        self._items: dict[tuple[str, str], str] = {}

    def get_secret(self, host: str, name: str) -> str | None:
        if name not in ALLOWED_SECRET_NAMES:
            raise CredentialStoreError("That credential type cannot be stored.")
        return self._items.get((host.lower(), name))

    def set_secret(self, host: str, name: str, value: str) -> None:
        self._items[(host.lower(), name)] = _validate_secret(name, value)

    def delete_secret(self, host: str, name: str) -> None:
        if name not in ALLOWED_SECRET_NAMES:
            raise CredentialStoreError("That credential type cannot be stored.")
        self._items.pop((host.lower(), name), None)


class KeyringCredentialStore:
    """Windows Credential Manager via the keyring package, or the platform equivalent."""

    def __init__(self, keyring_module: Any | None = None) -> None:
        if keyring_module is None:
            try:
                import keyring as imported_keyring
            except ImportError as exc:
                raise CredentialStoreError(
                    "The operating-system credential store is unavailable. Install the keyring package."
                ) from exc
            keyring_module = imported_keyring
        self._keyring = keyring_module

    def _item_name(self, host: str, name: str) -> str:
        if name not in ALLOWED_SECRET_NAMES:
            raise CredentialStoreError("That credential type cannot be stored.")
        return f"{host.lower()}:{name}"

    def get_secret(self, host: str, name: str) -> str | None:
        try:
            return self._keyring.get_password(SERVICE_NAME, self._item_name(host, name))
        except CredentialStoreError:
            raise
        except Exception as exc:
            raise CredentialStoreError("The operating-system credential store could not be read.") from exc

    def set_secret(self, host: str, name: str, value: str) -> None:
        checked = _validate_secret(name, value)
        try:
            self._keyring.set_password(SERVICE_NAME, self._item_name(host, name), checked)
        except CredentialStoreError:
            raise
        except Exception as exc:
            raise CredentialStoreError("The operating-system credential store could not save the credential.") from exc

    def delete_secret(self, host: str, name: str) -> None:
        item = self._item_name(host, name)
        try:
            self._keyring.delete_password(SERVICE_NAME, item)
        except CredentialStoreError:
            raise
        except Exception as exc:
            if exc.__class__.__name__ == "PasswordDeleteError":
                return
            raise CredentialStoreError(
                "The operating-system credential store could not remove the credential."
            ) from exc
