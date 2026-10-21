"""Portal adapter contract.

Implementations may use a documented administrator API or the built-in synthetic
demo. They do not guess authentication signatures or scan for accounts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from models.portal_models import AccountInfo, ChannelMetadata


class PortalAdapter(ABC):
    """Operations the inspection services can perform against one portal."""

    @property
    @abstractmethod
    def is_demo(self) -> bool:
        """True when results are synthetic and no network request is made."""

    @abstractmethod
    def connect(self) -> None:
        """Prepare a connection. This must not send credentials."""

    @abstractmethod
    def authenticate(self) -> None:
        """Authenticate with a documented method, or mark the demo session ready."""

    @abstractmethod
    def get_device_info(self) -> AccountInfo:
        """Return device fields exposed by the authorized API."""

    @abstractmethod
    def get_account_info(self) -> AccountInfo:
        """Return account fields exposed by the authorized API."""

    @abstractmethod
    def get_channel_metadata(self) -> ChannelMetadata:
        """Return channel catalogue metadata. Do not retrieve stream content."""

    @abstractmethod
    def disconnect(self) -> None:
        """Close the session and discard in-memory tokens."""
