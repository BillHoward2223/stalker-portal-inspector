"""Logging with credential redaction. HTTP libraries stay at warning level."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from security.redaction import RedactingFormatter
from services.app_paths import app_data_dir


def configure_logging(log_path: Path | None = None) -> Path:
    """Write redacted diagnostic logs to the user data directory and the console."""

    target = log_path or (app_data_dir() / "inspector.log")
    target.parent.mkdir(parents=True, exist_ok=True)
    formatter = RedactingFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    file_handler = RotatingFileHandler(target, maxBytes=512_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.INFO)
    root.addHandler(file_handler)
    root.addHandler(stream_handler)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    return target
