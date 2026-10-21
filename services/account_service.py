"""Merge the device and account payloads exposed by a portal adapter."""

from __future__ import annotations

from collections.abc import Callable

from adapters.base import PortalAdapter
from models.errors import UnsupportedEndpointError
from models.portal_models import AccountInfo

_FIELDS = (
    "portal_id",
    "mac_address",
    "status",
    "expires_at",
    "serial_number",
    "last_connection_at",
    "sncut",
    "dev1",
    "dev2",
)


def merge_accounts(preferred: AccountInfo | None, fallback: AccountInfo | None) -> AccountInfo:
    """Prefer the account endpoint and fill gaps from the device endpoint."""

    if preferred is None and fallback is None:
        return AccountInfo(auth_status="Authenticated", reported=False)
    if preferred is None:
        return fallback or AccountInfo(auth_status="Authenticated", reported=False)
    if fallback is None:
        return preferred
    values = {
        name: getattr(preferred, name) if getattr(preferred, name) is not None else getattr(fallback, name)
        for name in _FIELDS
    }
    meanings = dict(fallback.proprietary_meanings)
    meanings.update(preferred.proprietary_meanings)
    return AccountInfo(
        **values,
        proprietary_meanings=meanings,
        auth_status=preferred.auth_status or fallback.auth_status,
        reported=preferred.reported or fallback.reported,
    )


class AccountService:
    """Load account data. A missing specification entry is reported, not invented."""

    def __init__(self, adapter: PortalAdapter) -> None:
        self._adapter = adapter

    def load(self) -> AccountInfo:
        account = self._optional(self._adapter.get_account_info)
        device = self._optional(self._adapter.get_device_info)
        if account is None and device is None:
            return AccountInfo(auth_status="Authenticated", reported=False)
        return merge_accounts(account, device)

    def _optional(self, method: Callable[[], AccountInfo]) -> AccountInfo | None:
        try:
            return method()
        except UnsupportedEndpointError:
            return None
