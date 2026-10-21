"""Errors that are safe to show in the desktop interface."""


class PortalError(Exception):
    """Base error whose message contains no credentials or response bodies."""

    def __init__(self, user_message: str) -> None:
        super().__init__(user_message)
        self.user_message = user_message


class InvalidInputError(PortalError):
    """The user entered a URL, MAC address, or specification the app cannot use."""


class PortalConnectionError(PortalError):
    """DNS, timeout, or another network failure before a valid HTTP response."""


class TlsCertificateError(PortalError):
    """TLS certificate validation failed. Verification is never disabled."""


class AuthenticationFailedError(PortalError):
    """The portal rejected the supplied credentials."""


class PermissionDeniedError(PortalError):
    """The portal authenticated the caller but refused the requested resource."""


class SessionExpiredError(PortalError):
    """A session token expired and official renewal failed or is not defined."""


class UnsupportedEndpointError(PortalError):
    """The loaded specification does not declare the requested resource."""


class UnexpectedResponseError(PortalError):
    """The response was missing, redirected, oversized, or not valid JSON."""


class RateLimitError(PortalError):
    """The portal returned HTTP 429 and the request was not retried again."""


class PortalServerError(PortalError):
    """The portal returned an HTTP 5xx response after one retry."""


class PaginationError(PortalError):
    """Channel pages were incomplete, repeated, or larger than the safety cap."""


class ResourceNotFoundError(PortalError):
    """The portal returned HTTP 404 for a declared endpoint."""


class CredentialStoreError(PortalError):
    """The operating-system credential store could not complete the request."""
