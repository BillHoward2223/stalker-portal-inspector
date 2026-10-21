"""Application identity shared by the interface, logs, and HTTP user agent."""

APP_NAME = "Stalker / Ministra Portal Account Inspector"
APP_VERSION = "1.0.0"
USER_AGENT = f"StalkerPortalInspector/{APP_VERSION}"
MAX_RESPONSE_BYTES = 2_000_000
MAX_CHANNEL_PAGES = 50
MAX_CHANNEL_RECORDS = 20_000
MAX_AUTH_REFRESHES = 2
