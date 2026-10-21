"""Administrator-supplied API specification.

The documented adapter calls only endpoints declared here. It does not add
set-top-box methods, signatures, or hidden administrative routes.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from models.errors import InvalidInputError

logger = logging.getLogger(__name__)

_SEGMENT = re.compile(r"^(?:[A-Za-z0-9._~-]+|\{mac\}|\{serial\})$")
_DOTTED = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$")
_FIELD_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_QUERY_KEY = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
_QUERY_VALUE = re.compile(r"^[A-Za-z0-9_.:{}/-]{0,80}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")

MAX_SPEC_BYTES = 256_000


def validate_endpoint_path(path: str) -> None:
    """Reject absolute URLs, traversal, and placeholders other than {mac} or {serial}."""

    if (
        not path.startswith("/")
        or path.startswith("//")
        or ".." in path
        or "?" in path
        or "#" in path
        or "\\" in path
        or "://" in path
    ):
        raise ValueError("Endpoint path is not supported.")
    parts = path.split("/")
    if any(part == "" for part in parts[1:]):
        raise ValueError("Endpoint path is not supported.")
    for part in parts[1:]:
        if not _SEGMENT.fullmatch(part):
            raise ValueError("Endpoint path is not supported.")


def validate_dotted_path(path: str) -> None:
    if not _DOTTED.fullmatch(path):
        raise ValueError("Response field path is not supported.")


def _normalize_host(value: str) -> str:
    item = value.strip().lower().rstrip(".")
    if not item or not (_HOSTNAME.fullmatch(item) or _IPV4.fullmatch(item)):
        raise ValueError("Allowed hosts must be exact hostnames or IPv4 addresses.")
    return item


class PaginationSpec(BaseModel):
    """Page parameters for a declared channel endpoint."""

    model_config = ConfigDict(extra="forbid")

    page_param: str = Field(min_length=1, max_length=40)
    page_size_param: str | None = Field(default=None, max_length=40)
    page_size: int = Field(default=100, ge=1, le=500)
    items_path: str
    total_path: str | None = None
    start_page: int = Field(default=1, ge=0, le=10_000)

    @field_validator("page_param", "page_size_param")
    @classmethod
    def _param(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _QUERY_KEY.fullmatch(value):
            raise ValueError("Pagination parameter name is not supported.")
        return value

    @field_validator("items_path", "total_path")
    @classmethod
    def _paths(cls, value: str | None) -> str | None:
        if value is None:
            return None
        validate_dotted_path(value)
        return value


class EndpointSpec(BaseModel):
    """One HTTP operation the administrator explicitly allowed."""

    model_config = ConfigDict(extra="forbid")

    method: Literal["GET", "POST"]
    path: str
    query: dict[str, str] = Field(default_factory=dict)
    items_path: str | None = None
    pagination: PaginationSpec | None = None

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        validate_endpoint_path(value)
        return value

    @field_validator("items_path")
    @classmethod
    def _items_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        validate_dotted_path(value)
        return value

    @field_validator("query")
    @classmethod
    def _query(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 20:
            raise ValueError("Too many query parameters.")
        for key, item in value.items():
            if not _QUERY_KEY.fullmatch(key) or not _QUERY_VALUE.fullmatch(item) or ".." in item:
                raise ValueError("Unsupported query parameter.")
        return value


class LoginSpec(BaseModel):
    """A documented login and, when the server supports it, token refresh."""

    model_config = ConfigDict(extra="forbid")

    method: Literal["POST"] = "POST"
    path: str
    username_field: str = "username"
    password_field: str = "password"
    token_path: str
    expires_in_path: str | None = None
    refresh_path: str | None = None
    refresh_token_path: str | None = None
    refresh_token_field: str = "refresh_token"

    @field_validator("path", "refresh_path")
    @classmethod
    def _paths(cls, value: str | None) -> str | None:
        if value is None:
            return None
        validate_endpoint_path(value)
        return value

    @field_validator("token_path", "expires_in_path", "refresh_token_path")
    @classmethod
    def _response_paths(cls, value: str | None) -> str | None:
        if value is None:
            return None
        validate_dotted_path(value)
        return value

    @field_validator("username_field", "password_field", "refresh_token_field")
    @classmethod
    def _body_fields(cls, value: str) -> str:
        if not _FIELD_NAME.fullmatch(value):
            raise ValueError("Login field name is not supported.")
        return value


class AuthSpec(BaseModel):
    """Authentication declared by the administrator specification."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["none", "bearer", "api_key", "basic", "session"]
    header_name: str | None = None
    token_prefix: str = "Bearer"
    login: LoginSpec | None = None

    @field_validator("header_name")
    @classmethod
    def _header_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _HEADER_NAME.fullmatch(value):
            raise ValueError("Header name is not supported.")
        return value

    @field_validator("token_prefix")
    @classmethod
    def _token_prefix(cls, value: str) -> str:
        if len(value) > 32 or any(ord(character) < 32 for character in value):
            raise ValueError("Token prefix is not supported.")
        return value

    def required_secret_names(self) -> tuple[str, ...]:
        if self.type in {"basic", "session"}:
            return ("username", "password")
        if self.type == "bearer":
            return ("bearer_token",)
        if self.type == "api_key":
            return ("api_key",)
        return ()


class EndpointSet(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_info: EndpointSpec | None = None
    account_info: EndpointSpec | None = None
    channels: EndpointSpec | None = None


class AccountFieldMap(BaseModel):
    """Dotted paths for scalar account fields. Proprietary names are not included here."""

    model_config = ConfigDict(extra="forbid")

    portal_id: str | None = None
    mac_address: str | None = None
    status: str | None = None
    expires_at: str | None = None
    serial_number: str | None = None
    last_connection_at: str | None = None

    @model_validator(mode="after")
    def _check_paths(self) -> AccountFieldMap:
        for name in (
            "portal_id",
            "mac_address",
            "status",
            "expires_at",
            "serial_number",
            "last_connection_at",
        ):
            value = getattr(self, name)
            if value is not None:
                validate_dotted_path(value)
        return self


class ChannelFieldMap(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record_id: str
    name: str
    category: str | None = None
    is_live: str | None = None

    @model_validator(mode="after")
    def _check_paths(self) -> ChannelFieldMap:
        validate_dotted_path(self.record_id)
        validate_dotted_path(self.name)
        if self.category is not None:
            validate_dotted_path(self.category)
        if self.is_live is not None:
            validate_dotted_path(self.is_live)
        return self


class ConfirmedProprietaryField(BaseModel):
    """A vendor field that may be displayed only with an explicit meaning."""

    model_config = ConfigDict(extra="forbid")

    name: Literal["sncut", "dev1", "dev2"]
    response_path: str
    meaning: str = Field(min_length=12, max_length=300)

    @field_validator("response_path")
    @classmethod
    def _path(cls, value: str) -> str:
        validate_dotted_path(value)
        return value


class ApiSpec(BaseModel):
    """The complete administrator specification for one portal origin."""

    model_config = ConfigDict(extra="forbid")

    spec_version: Literal["1.0"]
    title: str = Field(min_length=3, max_length=120)
    allowed_hosts: list[str] = Field(min_length=1, max_length=10)
    auth: AuthSpec
    endpoints: EndpointSet
    field_map: AccountFieldMap = Field(default_factory=AccountFieldMap)
    channel_fields: ChannelFieldMap | None = None
    confirmed_proprietary_fields: list[ConfirmedProprietaryField] = Field(default_factory=list)

    @field_validator("allowed_hosts")
    @classmethod
    def _hosts(cls, value: list[str]) -> list[str]:
        cleaned = [_normalize_host(item) for item in value]
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("Allowed hosts must be unique.")
        return cleaned

    @model_validator(mode="after")
    def _cross_checks(self) -> ApiSpec:
        if self.auth.type == "session" and self.auth.login is None:
            raise ValueError("Session authentication requires a login endpoint.")
        login = self.auth.login
        if login is not None and login.refresh_path and not login.refresh_token_path:
            raise ValueError("Token refresh requires refresh_token_path.")
        names = [item.name for item in self.confirmed_proprietary_fields]
        if len(names) != len(set(names)):
            raise ValueError("Each proprietary field can be confirmed once.")
        channels = self.endpoints.channels
        if channels is not None:
            if self.channel_fields is None:
                raise ValueError("Channel metadata requires channel_fields.")
            has_items = bool(channels.items_path or (channels.pagination and channels.pagination.items_path))
            if not has_items:
                raise ValueError("The channel endpoint needs an items path.")
        return self


def load_api_spec(path: Path) -> ApiSpec:
    """Read a local specification file. Credentials do not belong in this file."""

    file_path = Path(path)
    if not file_path.is_file():
        raise InvalidInputError("Choose an API specification JSON file.")
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise InvalidInputError("The API specification file could not be read.") from exc
    if size > MAX_SPEC_BYTES:
        raise InvalidInputError("The API specification file is too large.")
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InvalidInputError("The API specification file could not be read as JSON.") from exc
    if not isinstance(data, dict):
        raise InvalidInputError("The API specification must be a JSON object.")
    try:
        return ApiSpec.model_validate(data)
    except ValidationError as exc:
        locations = ", ".join(
            f"{'.'.join(str(part) for part in error.get('loc', ()))}: {error.get('type')}"
            for error in exc.errors()
        )
        logger.info("API specification validation failed: %s", locations or "invalid")
        raise InvalidInputError(
            "The API specification is missing required fields or contains unsupported settings."
        ) from exc
