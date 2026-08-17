from __future__ import annotations

from pathlib import Path

import pytest

from getsploit.paths import api_key_path, database_path, home_path


def test_home_prefers_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("GETSPLOIT_HOME", str(tmp_path / "custom"))
    assert home_path() == tmp_path / "custom"
    assert database_path() == tmp_path / "custom" / "getsploit.db"
    assert api_key_path() == tmp_path / "custom" / "vulners.key"


def test_home_uses_legacy_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("GETSPLOIT_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert home_path() == tmp_path / ".getsploit"
