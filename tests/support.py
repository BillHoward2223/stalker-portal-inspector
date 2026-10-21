"""Shared builders for mocked portal tests. These tests never call a live service."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

import httpx

from models.api_spec import ApiSpec
from models.portal_models import AuthMethod, ConnectionSettings
from security.credentials import SecretBundle
from adapters.documented_api_adapter import DocumentedApiAdapter

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
MAC = "00:1A:79:00:00:01"
PORTAL = "https://portal.example.com"


def load_json(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def spec_data() -> dict:
    return json.loads((ROOT / "config" / "api_spec.example.json").read_text(encoding="utf-8"))


def make_spec(page_size: int = 2) -> ApiSpec:
    raw = spec_data()
    raw["endpoints"]["channels"]["pagination"]["page_size"] = page_size
    return ApiSpec.model_validate(raw)


def make_settings(**overrides: object) -> ConnectionSettings:
    values: dict[str, object] = {
        "portal_url": PORTAL,
        "auth_method": AuthMethod.DOCUMENTED_API,
        "mac_address": MAC,
        "timeout_seconds": 5,
    }
    values.update(overrides)
    return ConnectionSettings.model_validate(values)


def make_adapter(
    handler,
    *,
    spec: ApiSpec | None = None,
    secrets: SecretBundle | None = None,
    settings: ConnectionSettings | None = None,
    **kwargs: object,
) -> DocumentedApiAdapter:
    return DocumentedApiAdapter(
        settings or make_settings(),
        spec or make_spec(),
        secrets or SecretBundle(username="northwind-admin", password="synthetic-password"),
        transport=httpx.MockTransport(handler),
        sleeper=lambda _delay: None,
        **kwargs,
    )


def request_path(request: httpx.Request) -> str:
    return unquote(urlsplit(str(request.url)).path)


def request_query(request: httpx.Request) -> dict[str, str]:
    return dict(parse_qsl(urlsplit(str(request.url)).query))
