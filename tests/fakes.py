"""In-memory portal adapter used by service tests."""

from __future__ import annotations

from models.errors import AuthenticationFailedError, UnsupportedEndpointError
from models.portal_models import AccountInfo, AuthMethod, ChannelMetadata, ConnectionSettings

from adapters.base import PortalAdapter


class StubAdapter(PortalAdapter):
    def __init__(self) -> None:
        self._settings = ConnectionSettings(
            portal_url="https://portal.example.com",
            auth_method=AuthMethod.DOCUMENTED_API,
            mac_address="00:1A:79:00:00:01",
            timeout_seconds=5,
        )
        self.auth_calls = 0
        self.channel_calls = 0
        self.account: AccountInfo | None = None
        self.device: AccountInfo | None = None
        self.channels = ChannelMetadata(records=[])
        self.auth_error: Exception | None = None
        self.account_error: Exception | None = None
        self.device_error: Exception | None = None
        self.channel_error: Exception | None = None
        self.connected = False
        self.authenticated = False

    @property
    def is_demo(self) -> bool:
        return False

    def connect(self) -> None:
        self.connected = True

    def authenticate(self) -> None:
        self.auth_calls += 1
        if self.auth_error:
            raise self.auth_error
        self.authenticated = True

    def get_device_info(self) -> AccountInfo:
        if self.device_error:
            raise self.device_error
        if self.device is None:
            raise UnsupportedEndpointError("This API specification does not include device information.")
        return self.device

    def get_account_info(self) -> AccountInfo:
        if self.account_error:
            raise self.account_error
        if self.account is None:
            raise UnsupportedEndpointError("This API specification does not include account information.")
        return self.account

    def get_channel_metadata(self) -> ChannelMetadata:
        self.channel_calls += 1
        if self.channel_error:
            raise self.channel_error
        return self.channels

    def disconnect(self) -> None:
        self.connected = False
        self.authenticated = False
