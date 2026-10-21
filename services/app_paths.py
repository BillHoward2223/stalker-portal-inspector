"""Application data directory. Settings go here; secrets do not."""

from __future__ import annotations

import os
from pathlib import Path


def app_data_dir() -> Path:
    """Return the per-user configuration directory, creating it when needed."""

    if os.name == "nt":
        root = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    path = root / "StalkerPortalInspector"
    path.mkdir(parents=True, exist_ok=True)
    return path
