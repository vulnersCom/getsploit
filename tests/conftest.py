from __future__ import annotations

import sqlite3
import zipfile
from pathlib import Path

import pytest

from getsploit.models import Exploit


@pytest.fixture(autouse=True)
def isolate_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GETSPLOIT_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("VULNERS_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def isolate_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    # Rich reports is_terminal=True whenever either variable is present, and per
    # force-color.org it reads FORCE_COLOR=0 as "force color on". Clearing both keeps
    # captured output independent of the developer's or CI runner's environment.
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.delenv("TTY_COMPATIBLE", raising=False)


@pytest.fixture
def exploit() -> Exploit:
    return Exploit(
        id="EDB-ID:42",
        title="Example exploit",
        url="https://vulners.com/exploitdb/EDB-ID:42",
        published="2026-01-02T03:04:05Z",
        description="description",
        source_data="print('source')",
        collection="exploitdb",
    )


def create_legacy_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE VIRTUAL TABLE exploits USING FTS4(
                id, title, published, description, sourceData, vhref
            )
            """
        )
        connection.executemany(
            "INSERT INTO exploits VALUES (?, ?, ?, ?, ?, ?)",
            (
                (
                    "EDB-ID:42",
                    "WordPress example exploit",
                    "2026-01-02T03:04:05Z",
                    "remote code execution",
                    "print('source')",
                    "https://vulners.com/exploitdb/EDB-ID:42",
                ),
                (
                    "PACKETSTORM:7",
                    "Linux local exploit",
                    "2025-02-03T04:05:06Z",
                    "local privilege escalation",
                    "",
                    "https://vulners.com/packetstorm/PACKETSTORM:7",
                ),
            ),
        )


@pytest.fixture
def legacy_database(tmp_path: Path) -> Path:
    path = tmp_path / "legacy.db"
    create_legacy_database(path)
    return path


@pytest.fixture
def legacy_archive(legacy_database: Path, tmp_path: Path) -> Path:
    path = tmp_path / "getsploit.db.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(legacy_database, "nested/getsploit.db")
    return path
