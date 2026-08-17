from __future__ import annotations

import os
from pathlib import Path


def home_path() -> Path:
    configured = os.environ.get("GETSPLOIT_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".getsploit"


def database_path() -> Path:
    return home_path() / "getsploit.db"


def api_key_path() -> Path:
    return home_path() / "vulners.key"
