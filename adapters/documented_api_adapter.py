"""HTTP client that follows an administrator-supplied API specification.

Requests are limited to the specification's host allowlist and declared paths.
Certificate verification stays enabled. Redirects are not followed. Tokens are
kept in memory for the connection and discarded on disconnect.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

from app_info import MAX_AUTH_REFRESHES, MAX_CHANNEL_PAGES, MAX_CHANNEL_RECORDS, MAX_RESPONSE_BYTES, USER_AGENT
from models.api_spec import ApiSpec, EndpointSpec
from models.errors import (
    AuthenticationFailedError,
    InvalidInputError,
    PaginationError,
    PermissionDeniedError,
    PortalConnectionError,
    PortalError,
    PortalServerError,
    RateLimitError,
    ResourceNotFoundError,
    SessionExpiredError,
    TlsCertificateError,
    UnexpectedResponseError,
    UnsupportedEndpointError,
)
from models.portal_models import AccountInfo, ChannelMetadata, ChannelRecord, ConnectionSettings, portal_host
from security.credentials import SecretBundle

from adapters.base import PortalAdapter
from adapters.parsing import apply_placeholders, as_text, dig

logger = logging.getLogger(__name__)

_ACCOUNT_FIELDS = (
    "portal_id",
    "mac_address",
    "status",
    "expires_at",
    "serial_number",
    "last_connection_at",
)


def map_connect_error(exc: Exception) -> PortalError:
    text = str(exc).lower()
    if "certificate" in text or "tls" in text or "ssl" in text:
        return TlsCertificateError(
            "The portal TLS certificate could not be verified. Certificate checks stay enabled."
        )
    if any(phrase in text for phrase in ("getaddrinfo", "name or service not known", "nodename", "name resolution")):
        return PortalConnectionError("The portal hostname could not be resolved.")
    return PortalConnectionError("The application could not connect to the portal.")


def _retry_after_seconds(header: str | None) -> float | None:
    if header is None:
        return None
    text = header.strip()
    if text.isdigit():
        return float(text)
    return None


class DocumentedApiAdapter(PortalAdapter):
    """Execute the endpoints in an `ApiSpec` and map the declared fields."""

    def __init__(
        self,
        settings: ConnectionSettings,
        spec: ApiSpec,
        secrets: SecretBundle | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] | None = None,
        sleeper: Callable[[float], None] | None = None,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self._settings = settings
        self._spec = spec
        self._secrets = secrets or SecretBundle()
        self._transport = transport
        self._clock = clock or time.monotonic
        self._sleep = sleeper or time.sleep
        self._max_response_bytes = max_response_bytes
        self._client: httpx.Client | None = None
        self._connected = False
        self._authenticated = False
        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._token_deadline: float | None = None
        self._refresh_used = 0

    @property
    def is_demo(self) -> bool:
        return False

    @property
    def spec(self) -> ApiSpec:
        return self._spec

    def connect(self) -> None:
        if portal_host(self._settings.portal_url) not in self._spec.allowed_hosts:
            raise InvalidInputError("This API specification does not authorize requests to that portal host.")
        if self._client is not None:
            self._connected = True
            return
        client = httpx.Client(
            verify=True,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(self._settings.timeout_seconds),
            transport=self._transport,
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        )
        self._client = client
        self._connected = True

    def authenticate(self) -> None:
        if not self._connected:
            raise PortalConnectionError("Connect to the portal before authenticating.")
        auth_type = self._spec.auth.type
        if auth_type == "none":
            self._authenticated = True
            return
        if auth_type == "bearer":
            if not self._secrets.bearer_token:
                raise AuthenticationFailedError("Save a bearer token before connecting.")
            self._authenticated = True
            return
        if auth_type == "api_key":
            if not self._secrets.api_key:
                raise AuthenticationFailedError("Save an API key before connecting.")
            self._authenticated = True
            return
        if auth_type == "basic":
            if not self._secrets.username or not self._secrets.password:
                raise AuthenticationFailedError("Save a username and password before connecting.")
            self._authenticated = True
            return
        if auth_type == "session":
            self._login()
            self._authenticated = True
            return
        raise UnsupportedEndpointError("This authentication method is not supported.")

    def get_device_info(self) -> AccountInfo:
        endpoint = self._spec.endpoints.device_info
        if endpoint is None:
            raise UnsupportedEndpointError("This API specification does not include device information.")
        return self._map_account(self._request_endpoint(endpoint))

    def get_account_info(self) -> AccountInfo:
        endpoint = self._spec.endpoints.account_info
        if endpoint is None:
            raise UnsupportedEndpointError("This API specification does not include account information.")
        return self._map_account(self._request_endpoint(endpoint))

    def get_channel_metadata(self) -> ChannelMetadata:
        endpoint = self._spec.endpoints.channels
        if endpoint is None:
            raise UnsupportedEndpointError("This API specification does not include channel metadata.")
        if endpoint.pagination is None:
            payload = self._request_endpoint(endpoint)
            records = self._map_records(payload, endpoint.items_path or "")
            return self._metadata(records)
        return self._paginate(endpoint)

    def disconnect(self) -> None:
        client = self._client
        self._client = None
        self._connected = False
        self._authenticated = False
        self._access_token = None
        self._refresh_token = None
        self._token_deadline = None
        self._refresh_used = 0
        self._secrets.clear()
        if client is not None:
            client.close()

    def _login(self) -> None:
        login = self._spec.auth.login
        if login is None:
            raise InvalidInputError("The API specification does not define a login endpoint.")
        if not self._secrets.username or not self._secrets.password:
            raise AuthenticationFailedError("Save a username and password before connecting.")
        payload = {
            login.username_field: self._secrets.username,
            login.password_field: self._secrets.password,
        }
        body = self._request(login.method, login.path, json_body=payload, authenticated=False, allow_refresh=False)
        self._store_session(body)

    def _refresh(self) -> None:
        login = self._spec.auth.login
        if (
            login is None
            or not login.refresh_path
            or not self._refresh_token
            or self._refresh_used >= MAX_AUTH_REFRESHES
        ):
            raise SessionExpiredError("The session expired and could not be renewed.")
        self._refresh_used += 1
        body = self._request(
            "POST",
            login.refresh_path,
            json_body={login.refresh_token_field: self._refresh_token},
            authenticated=False,
            allow_refresh=False,
            check_expiry=False,
        )
        self._store_session(body)

    def _store_session(self, body: Any) -> None:
        login = self._spec.auth.login
        if login is None or not isinstance(body, dict):
            raise UnexpectedResponseError("The portal returned a response this application could not validate.")
        token = dig(body, login.token_path)
        if not isinstance(token, str) or not token.strip():
            raise UnexpectedResponseError("The login response did not include a session token.")
        self._access_token = token
        refresh = dig(body, login.refresh_token_path) if login.refresh_token_path else None
        self._refresh_token = refresh if isinstance(refresh, str) and refresh else None
        expires = dig(body, login.expires_in_path) if login.expires_in_path else None
        if isinstance(expires, int) and not isinstance(expires, bool) and expires >= 30:
            self._token_deadline = self._clock() + float(expires)
        else:
            self._token_deadline = None

    def _ensure_session_fresh(self) -> None:
        if self._spec.auth.type != "session" or self._token_deadline is None:
            return
        if self._clock() < self._token_deadline:
            return
        self._refresh()

    def _can_refresh(self) -> bool:
        login = self._spec.auth.login
        return bool(
            self._spec.auth.type == "session"
            and login is not None
            and login.refresh_path
            and self._refresh_token
            and self._refresh_used < MAX_AUTH_REFRESHES
        )

    def _request_endpoint(self, endpoint: EndpointSpec, extra_query: dict[str, str] | None = None) -> Any:
        self._require_auth()
        values = self._placeholder_values()
        path = apply_placeholders(endpoint.path, values, encode=True)
        query = {key: apply_placeholders(value, values, encode=False) for key, value in endpoint.query.items()}
        if extra_query:
            query.update(extra_query)
        return self._request(endpoint.method, path, query=query, authenticated=True)

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        authenticated: bool = True,
        allow_refresh: bool = True,
        allow_server_retry: bool = True,
        check_expiry: bool = True,
    ) -> Any:
        if self._client is None:
            raise PortalConnectionError("The portal connection is closed.")
        if check_expiry and authenticated:
            self._ensure_session_fresh()
        headers: dict[str, str] = {}
        content: bytes | None = None
        if json_body is not None:
            content = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authenticated:
            headers.update(self._auth_headers())
        url = self._settings.portal_url + path
        try:
            with self._client.stream(
                method,
                url,
                headers=headers,
                params=query or None,
                content=content,
            ) as response:
                status = response.status_code
                retry_after = response.headers.get("Retry-After")
                body = self._read_limited(response)
        except (InvalidInputError, UnexpectedResponseError):
            raise
        except httpx.TimeoutException:
            raise PortalConnectionError("The portal did not respond before the timeout.")
        except httpx.ConnectError as exc:
            raise map_connect_error(exc)
        except httpx.HTTPError:
            raise PortalConnectionError("The application could not complete the portal request.")

        logger.info("HTTP %s %s -> %s (%s bytes)", method, path, status, len(body))
        if status == 401:
            if authenticated and allow_refresh and self._can_refresh():
                self._refresh()
                return self._request(
                    method,
                    path,
                    query=query,
                    json_body=json_body,
                    authenticated=authenticated,
                    allow_refresh=False,
                    allow_server_retry=allow_server_retry,
                    check_expiry=False,
                )
            if self._spec.auth.type == "session" and self._access_token:
                raise SessionExpiredError("The session expired and could not be renewed.")
            raise AuthenticationFailedError("The portal rejected the credentials.")
        if status == 403:
            raise PermissionDeniedError(
                "The portal refused access. This account is not permitted to query that resource."
            )
        if status == 404:
            raise ResourceNotFoundError("The portal did not find a matching resource for this request.")
        if status == 429:
            delay = _retry_after_seconds(retry_after)
            if allow_server_retry and delay is not None and delay <= 2:
                self._sleep(delay)
                return self._request(
                    method,
                    path,
                    query=query,
                    json_body=json_body,
                    authenticated=authenticated,
                    allow_refresh=False,
                    allow_server_retry=False,
                    check_expiry=False,
                )
            raise RateLimitError("The portal asked the application to slow down. Try again later.")
        if 300 <= status < 400:
            raise UnexpectedResponseError("The portal redirected the request. Redirects are not followed.")
        if status >= 500:
            if allow_server_retry:
                return self._request(
                    method,
                    path,
                    query=query,
                    json_body=json_body,
                    authenticated=authenticated,
                    allow_refresh=allow_refresh,
                    allow_server_retry=False,
                    check_expiry=False,
                )
            raise PortalServerError("The portal returned a server error.")
        if status < 200 or status >= 300:
            raise UnexpectedResponseError("The portal returned a response this application could not validate.")
        return self._parse_json(body)

    def _read_limited(self, response: httpx.Response) -> bytes:
        declared = response.headers.get("Content-Length")
        if declared is not None and declared.isdigit() and int(declared) > self._max_response_bytes:
            raise UnexpectedResponseError("The portal response is larger than the supported limit.")
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > self._max_response_bytes:
                raise UnexpectedResponseError("The portal response is larger than the supported limit.")
            chunks.append(chunk)
        return b"".join(chunks)

    def _auth_headers(self) -> dict[str, str]:
        auth = self._spec.auth
        if auth.type == "bearer":
            return {"Authorization": f"Bearer {self._secrets.bearer_token}"}
        if auth.type == "api_key":
            return {auth.header_name or "X-API-Key": self._secrets.api_key or ""}
        if auth.type == "basic":
            raw = f"{self._secrets.username}:{self._secrets.password}".encode()
            return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}
        if auth.type == "session":
            if not self._access_token:
                raise AuthenticationFailedError("The session is not authenticated.")
            header_name = auth.header_name or "Authorization"
            prefix = auth.token_prefix.strip()
            value = f"{prefix} {self._access_token}".strip() if prefix else self._access_token
            return {header_name: value}
        return {}

    def _parse_json(self, body: bytes) -> Any:
        if not body:
            raise UnexpectedResponseError("The portal returned an empty response.")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise UnexpectedResponseError("The portal returned a response this application could not validate.")

    def _map_account(self, payload: Any) -> AccountInfo:
        if not isinstance(payload, dict):
            raise UnexpectedResponseError("The portal returned a response this application could not validate.")
        values = {
            name: as_text(dig(payload, getattr(self._spec.field_map, name)))
            for name in _ACCOUNT_FIELDS
        }
        meanings: dict[str, str] = {}
        for item in self._spec.confirmed_proprietary_fields:
            values[item.name] = as_text(dig(payload, item.response_path))
            meanings[item.name] = item.meaning
        return AccountInfo(
            **values,
            proprietary_meanings=meanings,
            auth_status="Authenticated",
            reported=True,
        )

    def _paginate(self, endpoint: EndpointSpec) -> ChannelMetadata:
        page_spec = endpoint.pagination
        if page_spec is None:
            raise UnsupportedEndpointError("This API specification does not include channel pagination.")
        collected: list[ChannelRecord] = []
        notes: list[str] = []
        page = page_spec.start_page
        previous_signature: tuple[str, ...] | None = None
        reported_total: int | None = None
        items_path = page_spec.items_path
        for _ in range(MAX_CHANNEL_PAGES):
            extra = {page_spec.page_param: str(page)}
            if page_spec.page_size_param:
                extra[page_spec.page_size_param] = str(page_spec.page_size)
            payload = self._request_endpoint(endpoint, extra_query=extra)
            if reported_total is None and page_spec.total_path:
                reported_total = self._require_total(dig(payload, page_spec.total_path))
            records = self._map_records(payload, items_path)
            if not records:
                break
            signature = tuple(record.record_id or "" for record in records)
            if previous_signature is not None and signature == previous_signature:
                raise PaginationError("Channel pagination stopped because the portal repeated a page.")
            previous_signature = signature
            collected.extend(records)
            if len(collected) > MAX_CHANNEL_RECORDS:
                raise PaginationError("Channel pagination stopped because the response was too large.")
            if reported_total is not None and len(collected) >= reported_total:
                break
            if page_spec.page_size_param and len(records) < page_spec.page_size:
                break
            page += 1
        else:
            raise PaginationError("Channel pagination stopped because too many pages were returned.")
        if reported_total is not None and len(collected) < reported_total:
            raise PaginationError(
                "Channel pagination stopped because the portal responses were incomplete or inconsistent."
            )
        if reported_total is not None and len(collected) > reported_total:
            notes.append(
                "The portal reported fewer records than it returned. Counts use the records that were actually returned."
            )
        return self._metadata(collected, notes)

    def _require_total(self, value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise UnexpectedResponseError("The portal returned a response this application could not validate.")
        return value

    def _map_records(self, payload: Any, items_path: str) -> list[ChannelRecord]:
        if not items_path:
            raise UnexpectedResponseError("The portal returned a response this application could not validate.")
        raw_items = dig(payload, items_path)
        if not isinstance(raw_items, list):
            raise UnexpectedResponseError("The portal returned a response this application could not validate.")
        fields = self._spec.channel_fields
        if fields is None:
            raise UnsupportedEndpointError("This API specification does not define channel fields.")
        records: list[ChannelRecord] = []
        for item in raw_items:
            if not isinstance(item, dict):
                raise UnexpectedResponseError("The portal returned a response this application could not validate.")
            live_value = dig(item, fields.is_live) if fields.is_live else None
            records.append(
                ChannelRecord(
                    record_id=as_text(dig(item, fields.record_id)),
                    name=as_text(dig(item, fields.name)),
                    category=as_text(dig(item, fields.category)) if fields.category else None,
                    is_live=live_value if isinstance(live_value, bool) else None,
                )
            )
        return records

    def _metadata(self, records: list[ChannelRecord], notes: list[str] | None = None) -> ChannelMetadata:
        fields = self._spec.channel_fields
        return ChannelMetadata(
            records=records,
            live_field_supported=bool(fields and fields.is_live),
            category_field_supported=bool(fields and fields.category),
            notes=list(notes or []),
        )

    def _placeholder_values(self) -> dict[str, str]:
        values = {"mac": self._settings.mac_address}
        if self._settings.serial_number:
            values["serial"] = self._settings.serial_number
        return values

    def _require_auth(self) -> None:
        if not self._authenticated:
            raise AuthenticationFailedError("Connect and authenticate before requesting portal data.")
