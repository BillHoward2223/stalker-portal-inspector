"""Channel counting, account merges, and the one-attempt authentication service."""

from __future__ import annotations

import pytest

from models.errors import AuthenticationFailedError, PaginationError, PermissionDeniedError, UnsupportedEndpointError
from models.portal_models import AccountInfo, ChannelMetadata, ChannelRecord
from services.account_service import AccountService
from services.authentication import AuthenticationService
from services.channel_service import ChannelService, summarize_channels
from services.inspection import run_inspection

from tests.fakes import StubAdapter


def test_duplicate_and_empty_catalogues() -> None:
    records = [
        ChannelRecord(record_id="ch-news", name="Northwind News HD", category="News", is_live=True),
        ChannelRecord(record_id="ch-news", name="Northwind News HD", category="News", is_live=True),
        ChannelRecord(record_id="ch-cinema", name="Northwind Cinema", category="Movies", is_live=False),
    ]
    counted = summarize_channels(records, live_field_supported=True, category_field_supported=True)
    assert counted.total_records == 3
    assert counted.unique_channels == 2
    assert counted.live_channels == 1
    assert counted.category_count == 2

    empty = summarize_channels([], live_field_supported=True, category_field_supported=False)
    assert empty.total_records == 0
    assert empty.unique_channels == 0
    assert empty.live_channels == 0
    assert empty.category_count is None


def test_unique_count_is_withheld_without_ids() -> None:
    records = [ChannelRecord(record_id=None, name="Northwind News HD", category="News", is_live=True)]
    counted = summarize_channels(records, live_field_supported=True, category_field_supported=True)
    assert counted.total_records == 1
    assert counted.unique_channels is None
    assert counted.live_channels is None
    assert "no channel id" in " ".join(counted.notes)


def test_account_merge_and_unsupported_endpoints() -> None:
    adapter = StubAdapter()
    adapter.account = AccountInfo(status="active", auth_status="Authenticated", reported=True)
    adapter.device = AccountInfo(
        mac_address="00:1A:79:00:00:01",
        serial_number="SN-NORTHWIND-1001",
        auth_status="Authenticated",
        reported=True,
    )
    merged = AccountService(adapter).load()
    assert merged.status == "active"
    assert merged.serial_number == "SN-NORTHWIND-1001"
    assert merged.expires_at is None

    adapter.account = None
    adapter.device = None
    missing = AccountService(adapter).load()
    assert missing.reported is False
    assert missing.status is None


def test_permission_failure_stops_the_inspection() -> None:
    adapter = StubAdapter()
    adapter.account_error = PermissionDeniedError("The portal refused access.")
    with pytest.raises(PermissionDeniedError):
        run_inspection(adapter)
    assert adapter.channel_calls == 0


def test_channel_pagination_failure_keeps_the_account() -> None:
    adapter = StubAdapter()
    adapter.account = AccountInfo(status="active", auth_status="Authenticated", reported=True)
    adapter.channel_error = PaginationError("Channel pagination stopped because the portal repeated a page.")
    report = run_inspection(adapter)
    assert report.account.status == "active"
    assert report.channels.available is False
    assert "repeated a page" in report.report_text


def test_authentication_failure_is_not_retried() -> None:
    adapter = StubAdapter()
    adapter.auth_error = AuthenticationFailedError("The portal rejected the credentials.")
    service = AuthenticationService(adapter)
    with pytest.raises(AuthenticationFailedError):
        service.establish()
    with pytest.raises(AuthenticationFailedError, match="attempt limit"):
        service.establish()
    assert adapter.auth_calls == 1


def test_channel_service_passes_support_flags() -> None:
    adapter = StubAdapter()
    adapter.channels = ChannelMetadata(
        records=[ChannelRecord(record_id="ch-1", name="Northwind One")],
        live_field_supported=False,
        category_field_supported=False,
    )
    catalogue = ChannelService(adapter).load()
    assert catalogue.unique_channels == 1
    assert catalogue.live_channels is None
    assert catalogue.category_count is None


def test_unsupported_device_endpoint_is_skipped() -> None:
    adapter = StubAdapter()
    adapter.device_error = UnsupportedEndpointError("This API specification does not include device information.")
    adapter.account = AccountInfo(status="active", auth_status="Authenticated")
    assert AccountService(adapter).load().status == "active"
