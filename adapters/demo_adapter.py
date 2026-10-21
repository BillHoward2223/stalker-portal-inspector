"""Synthetic portal data for interface development and tests.

This adapter never opens a network connection. Its records are fictional and
are labeled as a demo in the report.
"""

from __future__ import annotations

from models.errors import AuthenticationFailedError, PortalConnectionError
from models.portal_models import AccountInfo, ChannelMetadata, ChannelRecord, ConnectionSettings

from adapters.base import PortalAdapter

_DEMO_CHANNELS = (
    ChannelRecord(record_id="ch-news", name="Northwind News HD", category="News", is_live=True),
    ChannelRecord(record_id="ch-news", name="Northwind News HD", category="News", is_live=True),
    ChannelRecord(record_id="ch-sports", name="Northwind Sports", category="Sports", is_live=True),
    ChannelRecord(record_id="ch-cinema", name="Northwind Cinema", category="Movies", is_live=False),
)


class DemoAdapter(PortalAdapter):
    """Return a fixed fictional account and channel catalogue."""

    def __init__(self, settings: ConnectionSettings) -> None:
        self._settings = settings
        self._connected = False
        self._authenticated = False

    @property
    def is_demo(self) -> bool:
        return True

    def connect(self) -> None:
        self._connected = True

    def authenticate(self) -> None:
        if not self._connected:
            raise PortalConnectionError("Connect to the portal before authenticating.")
        self._authenticated = True

    def get_device_info(self) -> AccountInfo:
        self._require_auth()
        return AccountInfo(
            portal_id="synthetic-panel",
            mac_address=self._settings.mac_address,
            serial_number="SN-NORTHWIND-1001",
            auth_status="Demo (synthetic)",
            reported=True,
        )

    def get_account_info(self) -> AccountInfo:
        self._require_auth()
        return AccountInfo(
            portal_id="synthetic-panel",
            status="synthetic",
            expires_at="2026-12-31",
            auth_status="Demo (synthetic)",
            reported=True,
        )

    def get_channel_metadata(self) -> ChannelMetadata:
        self._require_auth()
        return ChannelMetadata(
            records=list(_DEMO_CHANNELS),
            live_field_supported=True,
            category_field_supported=True,
        )

    def disconnect(self) -> None:
        self._connected = False
        self._authenticated = False

    def _require_auth(self) -> None:
        if not self._authenticated:
            raise AuthenticationFailedError("Connect and authenticate before requesting portal data.")
