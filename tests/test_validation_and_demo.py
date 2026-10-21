"""Demo adapter and input validation. No portal is contacted."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from adapters.demo_adapter import DemoAdapter
from models.portal_models import AuthMethod, ConnectionSettings
from services.inspection import run_inspection
from services.report_service import report_document


def _demo_settings() -> ConnectionSettings:
    return ConnectionSettings(
        portal_url="https://demo.invalid",
        auth_method=AuthMethod.DEMO,
        mac_address="00-1a-79-00-00-01",
        serial_number="SN-USER-SHOULD-NOT-APPEAR",
        timeout_seconds=5,
    )


def test_demo_inspection_uses_synthetic_records_only() -> None:
    report = run_inspection(
        DemoAdapter(_demo_settings()),
        now=datetime(2026, 10, 22, 5, 10, tzinfo=timezone.utc),
    )
    assert report.demo is True
    assert report.mac_address == "00:1A:79:00:00:01"
    assert report.account.status == "synthetic"
    assert report.account.expires_at == "2026-12-31"
    assert report.account.serial_number == "SN-NORTHWIND-1001"
    assert report.account.sncut is None
    assert report.channels.total_records == 4
    assert report.channels.unique_channels == 3
    assert report.channels.live_channels == 2
    assert report.channels.category_count == 3
    text = report.report_text
    assert "https://demo.invalid" in text
    assert "SN-NORTHWIND-1001" in text
    assert "SN-USER-SHOULD-NOT-APPEAR" not in text
    assert "No portal was contacted" in text
    assert "Duplicate channel records were returned" in text
    document = report_document(report)
    assert document["session_connected_at"] == "2026-10-22T05:10:00+00:00"
    assert document["demo"] is True


def test_demo_source_does_not_open_http() -> None:
    source = Path(__file__).resolve().parents[1].joinpath("adapters", "demo_adapter.py").read_text(encoding="utf-8")
    assert "httpx" not in source
    assert "socket" not in source


@pytest.mark.parametrize(
    "portal_url",
    [
        "http://portal.example.com",
        "https://user:secret@portal.example.com",
        "https://portal.example.com/stalker",
        "https://portal.example.com?token=secret",
        "not a url",
    ],
)
def test_portal_url_must_be_an_https_origin(portal_url: str) -> None:
    with pytest.raises(ValidationError):
        ConnectionSettings(
            portal_url=portal_url,
            auth_method=AuthMethod.DEMO,
            mac_address="00:1A:79:00:00:01",
        )


@pytest.mark.parametrize(
    "mac_address",
    ["00:1A:79:00:00:*", "00:1A:79:00:00:01,00:1A:79:00:00:02", "00:1A:79:00:00", "not-a-mac"],
)
def test_mac_must_be_one_address(mac_address: str) -> None:
    with pytest.raises(ValidationError):
        ConnectionSettings(
            portal_url="https://portal.example.com",
            auth_method=AuthMethod.DEMO,
            mac_address=mac_address,
        )
