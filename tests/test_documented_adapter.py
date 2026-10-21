"""Documented adapter tests. HTTP is mocked and must stay on the fixture host."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from models.api_spec import ApiSpec, load_api_spec
from models.errors import (
    AuthenticationFailedError,
    InvalidInputError,
    PaginationError,
    PermissionDeniedError,
    PortalConnectionError,
    PortalServerError,
    RateLimitError,
    SessionExpiredError,
    TlsCertificateError,
    UnexpectedResponseError,
)
from security.credentials import SecretBundle
from services.inspection import run_inspection

from tests.support import (
    MAC,
    PORTAL,
    load_json,
    make_adapter,
    make_settings,
    make_spec,
    request_path,
    request_query,
    spec_data,
)


def _catalog(calls: list[tuple[str, str, dict[str, str]]]):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        calls.append((request.method, path, request_query(request)))
        if path == "/admin-api/v1/session":
            body = json.loads(request.content.decode())
            assert body == {"username": "northwind-admin", "password": "synthetic-password"}
            assert request.headers.get("Authorization") is None
            return httpx.Response(200, json=load_json("session.json"))
        if path == f"/admin-api/v1/devices/{MAC}":
            assert request.headers["Authorization"] == "Bearer synthetic-access-token"
            return httpx.Response(200, json=load_json("device.json"))
        if path == f"/admin-api/v1/accounts/{MAC}":
            assert request.headers["Authorization"] == "Bearer synthetic-access-token"
            return httpx.Response(200, json=load_json("account.json"))
        if path == "/admin-api/v1/channels":
            query = request_query(request)
            assert query["per_page"] == "2"
            page = query["page"]
            if page == "1":
                return httpx.Response(200, json=load_json("channels_page_1.json"))
            if page == "2":
                return httpx.Response(200, json=load_json("channels_page_2.json"))
        raise AssertionError(path)

    return handler


def test_successful_inspection_counts_pages_and_hides_unconfirmed_fields(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("INFO")
    calls: list[tuple[str, str, dict[str, str]]] = []
    adapter = make_adapter(_catalog(calls))
    report = run_inspection(adapter)
    pages = [query.get("page") for _method, path, query in calls if path == "/admin-api/v1/channels"]
    assert pages == ["1", "2"]
    assert report.account.status == "active"
    assert report.account.expires_at == "2026-12-31"
    assert report.account.serial_number == "SN-NORTHWIND-1001"
    assert report.account.portal_id == "panel-northwind"
    assert report.account.last_connection_at == "2026-04-02T08:30:00Z"
    assert report.account.sncut is None
    assert report.account.dev1 is None
    assert report.account.dev2 is None
    assert report.channels.total_records == 3
    assert report.channels.unique_channels == 3
    assert report.channels.live_channels == 2
    assert report.channels.category_count == 3
    assert "DO-NOT-DISPLAY" not in report.report_text
    assert "synthetic-access-token" not in caplog.text
    assert "synthetic-password" not in caplog.text
    assert "SNCUT, DEV1, DEV2 are not shown" in report.report_text
    adapter.disconnect()
    assert adapter._access_token is None


def test_login_failure_is_not_retried() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(401)

    adapter = make_adapter(handler)
    adapter.connect()
    with pytest.raises(AuthenticationFailedError):
        adapter.authenticate()
    assert calls["n"] == 1


def test_expired_session_refreshes_once() -> None:
    state = {"account": 0, "refresh": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        if path == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        if path == "/admin-api/v1/session/refresh":
            state["refresh"] += 1
            body = json.loads(request.content.decode())
            assert body == {"refresh_token": "synthetic-refresh-token"}
            return httpx.Response(200, json=load_json("session_refreshed.json"))
        if path == f"/admin-api/v1/accounts/{MAC}":
            state["account"] += 1
            if state["account"] == 1:
                return httpx.Response(401)
            assert request.headers["Authorization"] == "Bearer synthetic-access-token-2"
            return httpx.Response(200, json=load_json("account.json"))
        raise AssertionError(path)

    adapter = make_adapter(handler)
    adapter.connect()
    adapter.authenticate()
    account = adapter.get_account_info()
    assert account.status == "active"
    assert state == {"account": 2, "refresh": 1}


def test_failed_refresh_does_not_loop() -> None:
    state = {"refresh": 0, "account": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        if path == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        if path == "/admin-api/v1/session/refresh":
            state["refresh"] += 1
            return httpx.Response(401)
        if path.startswith("/admin-api/v1/accounts/"):
            state["account"] += 1
            return httpx.Response(401)
        raise AssertionError(path)

    adapter = make_adapter(handler)
    adapter.connect()
    adapter.authenticate()
    with pytest.raises(SessionExpiredError):
        adapter.get_account_info()
    assert state == {"refresh": 1, "account": 1}


def test_permission_failure_is_not_retried() -> None:
    calls = {"account": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        if path == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        calls["account"] += 1
        return httpx.Response(403)

    adapter = make_adapter(handler)
    adapter.connect()
    adapter.authenticate()
    with pytest.raises(PermissionDeniedError):
        adapter.get_account_info()
    assert calls["account"] == 1


def test_missing_account_fields_stay_unavailable() -> None:
    raw = spec_data()
    raw["endpoints"]["device_info"] = None
    spec = ApiSpec.model_validate(raw)

    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        if path == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        if path.startswith("/admin-api/v1/accounts/"):
            return httpx.Response(200, json=load_json("account_missing.json"))
        if path == "/admin-api/v1/channels":
            return httpx.Response(200, json=load_json("channels_empty.json"))
        raise AssertionError(path)

    report = run_inspection(make_adapter(handler, spec=spec))
    assert report.account.status == "active"
    assert report.account.expires_at is None
    assert report.account.serial_number is None
    assert report.account.portal_id is None
    assert f"{'Expires':<20}Not available" in report.report_text


def test_empty_channel_catalogue() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        if path == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        if path.startswith("/admin-api/v1/devices/"):
            return httpx.Response(200, json=load_json("device.json"))
        if path.startswith("/admin-api/v1/accounts/"):
            return httpx.Response(200, json=load_json("account.json"))
        if path == "/admin-api/v1/channels":
            return httpx.Response(200, json=load_json("channels_empty.json"))
        raise AssertionError(path)

    report = run_inspection(make_adapter(handler, spec=make_spec(page_size=50)))
    assert report.channels.total_records == 0
    assert report.channels.unique_channels == 0
    assert report.channels.live_channels == 0
    assert report.channels.category_count == 0
    assert "empty channel catalogue" in report.report_text


def test_duplicate_channel_records_are_counted_separately() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        if path == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        if path == "/admin-api/v1/channels":
            assert request_query(request)["page"] == "1"
            return httpx.Response(200, json=load_json("channels_duplicates.json"))
        raise AssertionError(path)

    raw = spec_data()
    raw["endpoints"]["device_info"] = None
    raw["endpoints"]["account_info"] = None
    raw["endpoints"]["channels"]["pagination"]["page_size"] = 50
    adapter = make_adapter(handler, spec=ApiSpec.model_validate(raw))
    adapter.connect()
    adapter.authenticate()
    metadata = adapter.get_channel_metadata()
    assert len(metadata.records) == 2
    assert metadata.records[0].record_id == metadata.records[1].record_id


def test_incomplete_pagination_is_not_reported_as_complete() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        if path == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        if path.startswith("/admin-api/v1/accounts/"):
            return httpx.Response(200, json=load_json("account.json"))
        if path.startswith("/admin-api/v1/devices/"):
            return httpx.Response(200, json=load_json("device.json"))
        if path == "/admin-api/v1/channels":
            if request_query(request)["page"] == "1":
                return httpx.Response(200, json=load_json("channels_page_1.json") | {"meta": {"total": 4}})
            return httpx.Response(200, json=load_json("channels_empty.json") | {"meta": {"total": 4}})
        raise AssertionError(path)

    report = run_inspection(make_adapter(handler))
    assert report.account.status == "active"
    assert report.channels.available is False
    assert report.channels.total_records is None
    assert "incomplete" in (report.channels.unavailable_reason or "")


def test_repeated_page_stops_pagination() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        if path == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        if path == "/admin-api/v1/channels":
            payload = load_json("channels_page_1.json")
            payload["meta"]["total"] = 10
            return httpx.Response(200, json=payload)
        raise AssertionError(path)

    raw = spec_data()
    raw["endpoints"]["device_info"] = None
    raw["endpoints"]["account_info"] = None
    raw["endpoints"]["channels"]["pagination"]["page_size"] = 2
    adapter = make_adapter(handler, spec=ApiSpec.model_validate(raw))
    adapter.connect()
    adapter.authenticate()
    with pytest.raises(PaginationError):
        adapter.get_channel_metadata()


def test_malformed_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request_path(request) == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        return httpx.Response(200, content=Path(__file__).parent.joinpath("fixtures", "malformed.txt").read_bytes())

    adapter = make_adapter(handler)
    adapter.connect()
    adapter.authenticate()
    with pytest.raises(UnexpectedResponseError):
        adapter.get_account_info()


def test_timeout_is_reported_without_a_retry() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if request_path(request) == "/admin-api/v1/session":
            raise httpx.ReadTimeout("timed out")
        raise AssertionError("data should not be requested")

    adapter = make_adapter(handler)
    adapter.connect()
    with pytest.raises(PortalConnectionError, match="timeout"):
        adapter.authenticate()
    assert calls["n"] == 1


def test_tls_and_dns_errors_keep_verification_enabled() -> None:
    def tls(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("certificate verify failed")

    def dns(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("getaddrinfo failed: Name or service not known")

    tls_adapter = make_adapter(tls)
    tls_adapter.connect()
    with pytest.raises(TlsCertificateError, match="stay enabled"):
        tls_adapter.authenticate()

    dns_adapter = make_adapter(dns)
    dns_adapter.connect()
    with pytest.raises(PortalConnectionError, match="could not be resolved"):
        dns_adapter.authenticate()


def test_rate_limit_and_server_error_retry_once() -> None:
    slow = {"n": 0}
    brief = {"n": 0}
    server = {"n": 0}

    def slow_handler(request: httpx.Request) -> httpx.Response:
        if request_path(request) == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        slow["n"] += 1
        return httpx.Response(429, headers={"Retry-After": "30"})

    def brief_handler(request: httpx.Request) -> httpx.Response:
        if request_path(request) == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        brief["n"] += 1
        if brief["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json=load_json("account.json"))

    def server_handler(request: httpx.Request) -> httpx.Response:
        if request_path(request) == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        server["n"] += 1
        return httpx.Response(500)

    slow_adapter = make_adapter(slow_handler)
    slow_adapter.connect()
    slow_adapter.authenticate()
    with pytest.raises(RateLimitError):
        slow_adapter.get_account_info()
    assert slow["n"] == 1

    brief_adapter = make_adapter(brief_handler)
    brief_adapter.connect()
    brief_adapter.authenticate()
    assert brief_adapter.get_account_info().status == "active"
    assert brief["n"] == 2

    failed = make_adapter(server_handler)
    failed.connect()
    failed.authenticate()
    with pytest.raises(PortalServerError):
        failed.get_account_info()
    assert server["n"] == 2


def test_redirects_are_not_followed() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if request_path(request) == "/admin-api/v1/session":
            return httpx.Response(302, headers={"Location": f"{PORTAL}/other"})
        raise AssertionError("redirect target must not be requested")

    adapter = make_adapter(handler)
    adapter.connect()
    assert adapter._client is not None
    assert adapter._client.follow_redirects is False
    assert getattr(adapter._client, "trust_env", getattr(adapter._client, "_trust_env", None)) is False
    with pytest.raises(UnexpectedResponseError, match="not followed"):
        adapter.authenticate()
    assert calls["n"] == 1


def test_response_size_is_limited() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request_path(request) == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        return httpx.Response(200, content=b"{" + b"x" * 800)

    adapter = make_adapter(handler, max_response_bytes=500)
    adapter.connect()
    adapter.authenticate()
    with pytest.raises(UnexpectedResponseError, match="larger than the supported limit"):
        adapter.get_account_info()


def test_host_outside_the_specification_is_rejected_before_a_request() -> None:
    calls = {"n": 0}

    def handler(_request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(200, json={})

    adapter = make_adapter(handler, settings=make_settings(portal_url="https://other.example"))
    with pytest.raises(InvalidInputError, match="does not authorize"):
        adapter.connect()
    assert calls["n"] == 0


def test_missing_channel_endpoint_is_reported_instead_of_guessed() -> None:
    raw = spec_data()
    raw["endpoints"]["channels"] = None
    raw["channel_fields"] = None

    def handler(request: httpx.Request) -> httpx.Response:
        if request_path(request) == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        if "/channels" in request_path(request):
            raise AssertionError("undeclared channel endpoint was called")
        if request_path(request).startswith("/admin-api/v1/accounts/"):
            return httpx.Response(200, json=load_json("account.json"))
        if request_path(request).startswith("/admin-api/v1/devices/"):
            return httpx.Response(200, json=load_json("device.json"))
        raise AssertionError(request_path(request))

    report = run_inspection(make_adapter(handler, spec=ApiSpec.model_validate(raw)))
    assert report.channels.available is False
    assert "does not include channel metadata" in (report.channels.unavailable_reason or "")


def test_bearer_token_rejection_does_not_refresh() -> None:
    raw = spec_data()
    raw["auth"] = {"type": "bearer", "token_prefix": "Bearer"}
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        assert request.headers["Authorization"] == "Bearer synthetic-bearer-token"
        return httpx.Response(401)

    adapter = make_adapter(
        handler,
        spec=ApiSpec.model_validate(raw),
        secrets=SecretBundle(bearer_token="synthetic-bearer-token"),
    )
    adapter.connect()
    adapter.authenticate()
    with pytest.raises(AuthenticationFailedError):
        adapter.get_account_info()
    assert calls["n"] == 1


def test_confirmed_proprietary_field_is_shown_with_its_meaning() -> None:
    raw = spec_data()
    raw["confirmed_proprietary_fields"] = [
        {
            "name": "sncut",
            "response_path": "sncut",
            "meaning": "Vendor-defined subscriber marker from the supplied specification.",
        }
    ]
    raw["endpoints"]["device_info"] = None

    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        if path == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        if path.startswith("/admin-api/v1/accounts/"):
            return httpx.Response(200, json={"subscription": {"status": "active"}, "sncut": "CUT-100"})
        if path == "/admin-api/v1/channels":
            return httpx.Response(200, json=load_json("channels_empty.json"))
        raise AssertionError(path)

    report = run_inspection(make_adapter(handler, spec=ApiSpec.model_validate(raw)))
    assert report.account.sncut == "CUT-100"
    assert "CUT-100" in report.report_text
    assert "Vendor-defined subscriber marker" in report.report_text
    assert "DEV1, DEV2 are not shown" in report.report_text
    assert report.account.dev1 is None


def test_serial_placeholder_is_not_sent_when_the_serial_is_absent() -> None:
    raw = spec_data()
    raw["endpoints"]["device_info"]["path"] = "/admin-api/v1/devices/{serial}"
    calls = {"device": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request_path(request) == "/admin-api/v1/session":
            return httpx.Response(200, json=load_json("session.json"))
        calls["device"] += 1
        raise AssertionError("device endpoint should not be called")

    adapter = make_adapter(handler, spec=ApiSpec.model_validate(raw))
    adapter.connect()
    adapter.authenticate()
    with pytest.raises(InvalidInputError, match="serial"):
        adapter.get_device_info()
    assert calls["device"] == 0


def test_example_specification_rejects_undocumented_extensions(tmp_path: Path) -> None:
    spec = load_api_spec(Path(__file__).resolve().parents[1] / "config" / "api_spec.example.json")
    assert spec.allowed_hosts == ["portal.example.com"]
    assert spec.confirmed_proprietary_fields == []
    raw = spec_data()
    raw["endpoints"]["device_info"]["path"] = "/admin-api/v1/../../devices"
    broken = tmp_path / "spec.json"
    broken.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(InvalidInputError, match="unsupported settings"):
        load_api_spec(broken)
    raw = spec_data()
    raw["handshake"] = {"enabled": True}
    broken.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(InvalidInputError):
        load_api_spec(broken)


def test_token_deadline_triggers_one_refresh() -> None:
    clock = {"now": 1_000.0}
    state = {"refresh": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request_path(request)
        if path == "/admin-api/v1/session":
            payload = load_json("session.json")
            payload["expires_in"] = 30
            return httpx.Response(200, json=payload)
        if path == "/admin-api/v1/session/refresh":
            state["refresh"] += 1
            payload = load_json("session_refreshed.json")
            payload["expires_in"] = 30
            return httpx.Response(200, json=payload)
        if path.startswith("/admin-api/v1/accounts/"):
            assert request.headers["Authorization"] == "Bearer synthetic-access-token-2"
            return httpx.Response(200, json=load_json("account.json"))
        raise AssertionError(path)

    adapter = make_adapter(handler, clock=lambda: clock["now"])
    adapter.connect()
    adapter.authenticate()
    clock["now"] = 1_031.0
    assert adapter.get_account_info().status == "active"
    assert state["refresh"] == 1
