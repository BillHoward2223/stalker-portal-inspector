"""Connection settings and the account/channel values an authorized API can return."""

from __future__ import annotations

import re
from enum import Enum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from models.errors import InvalidInputError

_MAC = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")


class AuthMethod(str, Enum):
    """How this application should obtain data. This is not a portal protocol list."""

    DEMO = "demo"
    DOCUMENTED_API = "documented_api"


def normalize_mac(value: str) -> str:
    """Accept one MAC address and return it as uppercase colon-separated hex."""

    raw = value.strip().upper().replace("-", ":")
    if not _MAC.fullmatch(raw):
        raise InvalidInputError("Enter one device MAC address in the form 00:1A:79:00:00:01.")
    return raw


def macs_equivalent(entered: str, reported: str | None) -> bool:
    """Return whether an API-reported MAC is the same device address that was entered."""

    if reported is None:
        return True
    try:
        return normalize_mac(reported) == normalize_mac(entered)
    except InvalidInputError:
        return False


def validate_portal_url(value: str) -> str:
    """Require an HTTPS origin with no embedded credentials, path, or query."""

    text = value.strip()
    if not text or len(text) > 500 or any(ord(character) < 32 for character in text):
        raise InvalidInputError("Enter a valid HTTPS portal URL.")
    parsed = urlsplit(text)
    host = parsed.hostname
    if parsed.scheme != "https" or not host:
        raise InvalidInputError("Enter a valid HTTPS portal URL. HTTP portals are not accepted.")
    if parsed.username or parsed.password:
        raise InvalidInputError("The portal URL must not contain embedded credentials.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise InvalidInputError("Enter the portal origin only, for example https://portal.example.com.")
    normalized_host = host.lower().rstrip(".")
    if not (_HOSTNAME.fullmatch(normalized_host) or _IPV4.fullmatch(normalized_host)):
        raise InvalidInputError("Enter a valid HTTPS portal URL.")
    return text.rstrip("/")


def portal_host(value: str) -> str:
    """Return the lowercase hostname from an already validated portal URL."""

    host = urlsplit(value).hostname
    if host is None:
        raise InvalidInputError("Enter a valid HTTPS portal URL.")
    return host.lower().rstrip(".")


class ConnectionSettings(BaseModel):
    """Non-secret connection inputs. Passwords and tokens stay in the credential store."""

    model_config = ConfigDict(extra="forbid")

    portal_url: str
    auth_method: AuthMethod
    mac_address: str
    serial_number: str | None = None
    timeout_seconds: float = Field(default=15.0, ge=3.0, le=60.0)
    spec_path: str | None = None

    @field_validator("portal_url")
    @classmethod
    def _portal_url(cls, value: str) -> str:
        try:
            return validate_portal_url(value)
        except InvalidInputError as exc:
            raise ValueError(exc.user_message) from exc

    @field_validator("mac_address")
    @classmethod
    def _mac_address(cls, value: str) -> str:
        try:
            return normalize_mac(value)
        except InvalidInputError as exc:
            raise ValueError(exc.user_message) from exc

    @field_validator("serial_number")
    @classmethod
    def _serial_number(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = value.strip()
        if not text:
            return None
        if len(text) > 128 or any(ord(character) < 32 for character in text):
            raise ValueError("The serial number contains unsupported characters.")
        return text


class AccountInfo(BaseModel):
    """Account fields mapped from a documented response. Missing values stay None."""

    model_config = ConfigDict(extra="forbid")

    portal_id: str | None = None
    mac_address: str | None = None
    status: str | None = None
    expires_at: str | None = None
    serial_number: str | None = None
    sncut: str | None = None
    dev1: str | None = None
    dev2: str | None = None
    proprietary_meanings: dict[str, str] = Field(default_factory=dict)
    auth_status: str = "Not authenticated"
    last_connection_at: str | None = None
    reported: bool = True


class ChannelRecord(BaseModel):
    """One channel metadata row. Stream addresses are never represented."""

    model_config = ConfigDict(extra="forbid")

    record_id: str | None = None
    name: str | None = None
    category: str | None = None
    is_live: bool | None = None


class ChannelMetadata(BaseModel):
    """Channel rows plus whether the specification defines live and category fields."""

    model_config = ConfigDict(extra="forbid")

    records: list[ChannelRecord] = Field(default_factory=list)
    live_field_supported: bool = False
    category_field_supported: bool = False
    notes: list[str] = Field(default_factory=list)


class ChannelCatalogue(BaseModel):
    """Counted channel metadata. None means the count cannot be calculated honestly."""

    model_config = ConfigDict(extra="forbid")

    available: bool = True
    unavailable_reason: str | None = None
    total_records: int | None = None
    unique_channels: int | None = None
    live_channels: int | None = None
    category_count: int | None = None
    records: list[ChannelRecord] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    @classmethod
    def unavailable(cls, reason: str) -> ChannelCatalogue:
        return cls(available=False, unavailable_reason=reason)


class InspectionReport(BaseModel):
    """The result shown in the report panel and written to a redacted JSON export."""

    model_config = ConfigDict(extra="forbid")

    portal_url: str
    mac_address: str
    spec_title: str | None = None
    account: AccountInfo
    channels: ChannelCatalogue
    demo: bool
    notices: list[str] = Field(default_factory=list)
    session_connected_at: str
    report_text: str = ""
