"""Single-attempt authentication. Portal-level token refresh is capped separately."""

from __future__ import annotations

from adapters.base import PortalAdapter
from models.errors import AuthenticationFailedError


class AuthenticationService:
    """Connect and authenticate once. A failed attempt is not repeated automatically."""

    def __init__(self, adapter: PortalAdapter) -> None:
        self._adapter = adapter
        self.attempts = 0

    def establish(self) -> None:
        self._adapter.connect()
        if self.attempts >= 1:
            raise AuthenticationFailedError(
                "Authentication was not retried because the attempt limit was reached."
            )
        self.attempts += 1
        self._adapter.authenticate()
