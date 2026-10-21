"""Portal adapters."""

from adapters.base import PortalAdapter
from adapters.demo_adapter import DemoAdapter
from adapters.documented_api_adapter import DocumentedApiAdapter

__all__ = ["DemoAdapter", "DocumentedApiAdapter", "PortalAdapter"]
