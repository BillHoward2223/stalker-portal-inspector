"""Run one inspection and assemble a report the interface can render."""

from __future__ import annotations

from datetime import datetime

from adapters.base import PortalAdapter
from models.errors import (
    PaginationError,
    PortalConnectionError,
    PortalServerError,
    RateLimitError,
    ResourceNotFoundError,
    UnexpectedResponseError,
    UnsupportedEndpointError,
)
from models.portal_models import ChannelCatalogue, InspectionReport, macs_equivalent
from services.account_service import AccountService
from services.authentication import AuthenticationService
from services.channel_service import ChannelService
from services.report_service import format_report, proprietary_notice

_CHANNEL_FAILURES = (
    UnsupportedEndpointError,
    PaginationError,
    RateLimitError,
    PortalServerError,
    UnexpectedResponseError,
    PortalConnectionError,
    ResourceNotFoundError,
)


def run_inspection(adapter: PortalAdapter, *, now: datetime | None = None) -> InspectionReport:
    """Authenticate once, then read account and channel metadata."""

    AuthenticationService(adapter).establish()
    account = AccountService(adapter).load()
    notices: list[str] = []
    if adapter.is_demo:
        notices.append("Demo mode is showing synthetic data. No portal was contacted.")
    proprietary = proprietary_notice(account)
    if proprietary:
        notices.append(proprietary)
    if not account.reported:
        notices.append("The API specification does not expose account or device information.")
    if account.mac_address and not macs_equivalent(adapter_mac(adapter), account.mac_address):
        notices.append("The API reported a different MAC address from the one requested. Both values are shown.")

    try:
        channels = ChannelService(adapter).load()
    except _CHANNEL_FAILURES as exc:
        channels = ChannelCatalogue.unavailable(exc.user_message)
    if channels.available and channels.total_records == 0:
        notices.append("The portal returned an empty channel catalogue.")

    connected_at = (now or datetime.now().astimezone()).isoformat(timespec="seconds")
    report = InspectionReport(
        portal_url=adapter_url(adapter),
        mac_address=adapter_mac(adapter),
        spec_title=adapter_spec_title(adapter),
        account=account,
        channels=channels,
        demo=adapter.is_demo,
        notices=notices,
        session_connected_at=connected_at,
    )
    report.report_text = format_report(report)
    return report


def adapter_url(adapter: PortalAdapter) -> str:
    settings = getattr(adapter, "_settings", None)
    if settings is None:
        return "Not available"
    return str(settings.portal_url)


def adapter_mac(adapter: PortalAdapter) -> str:
    settings = getattr(adapter, "_settings", None)
    if settings is None:
        return "Not available"
    return str(settings.mac_address)


def adapter_spec_title(adapter: PortalAdapter) -> str | None:
    spec = getattr(adapter, "spec", None)
    if spec is None:
        return None
    return str(spec.title)
