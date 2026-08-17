from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from getsploit import credentials
from getsploit.credentials import CredentialError, load_api_key, store_api_key


@pytest.fixture
def app_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    monkeypatch.setenv("GETSPLOIT_HOME", str(home))
    monkeypatch.delenv("VULNERS_API_KEY", raising=False)
    return home


def test_load_priority_and_missing_file(monkeypatch: pytest.MonkeyPatch, app_home: Path) -> None:
    assert load_api_key() is None
    app_home.mkdir()
    (app_home / "vulners.key").write_text(" saved \n")
    assert load_api_key() == "saved"
    if os.name != "nt":
        assert (app_home / "vulners.key").stat().st_mode & 0o777 == 0o600
    (app_home / "vulners.key").write_text(" \n")
    assert load_api_key() is None
    monkeypatch.setenv("VULNERS_API_KEY", " environment ")
    assert load_api_key() == "environment"


def test_store_is_atomic_and_private(app_home: Path) -> None:
    store_api_key("secret")
    key_path = app_home / "vulners.key"
    assert key_path.read_text() == "secret"
    if os.name != "nt":
        assert key_path.stat().st_mode & 0o777 == 0o600
        assert app_home.stat().st_mode & 0o777 == 0o700


def test_store_skips_posix_permissions_on_windows(
    monkeypatch: pytest.MonkeyPatch, app_home: Path
) -> None:
    monkeypatch.setattr(credentials, "_WINDOWS", True)
    store_api_key("secret")
    assert (app_home / "vulners.key").read_text() == "secret"


def test_load_rejects_non_regular_key_path(app_home: Path, tmp_path: Path) -> None:
    app_home.mkdir()
    (app_home / "vulners.key").symlink_to(tmp_path / "missing")
    with pytest.raises(CredentialError, match="not a regular file"):
        load_api_key()

    (app_home / "vulners.key").unlink()
    (app_home / "vulners.key").mkdir()
    with pytest.raises(CredentialError, match="not a regular file"):
        load_api_key()


def test_load_rejects_non_utf8_key_file(app_home: Path) -> None:
    app_home.mkdir()
    # PowerShell's `>` writes UTF-16, so a hand-made key file is a realistic input.
    (app_home / "vulners.key").write_bytes(("A" * 64).encode("utf-16"))
    with pytest.raises(CredentialError, match="not valid UTF-8"):
        load_api_key()


def test_load_does_not_block_on_a_fifo_key_path(app_home: Path) -> None:
    if not hasattr(os, "mkfifo"):  # Windows has no FIFOs to defend against.
        return
    app_home.mkdir()
    os.mkfifo(app_home / "vulners.key")
    # Without O_NONBLOCK the open waits for a writer that never arrives, so a
    # regression here shows up as this test hanging rather than failing.
    with pytest.raises(CredentialError, match="not a regular file"):
        load_api_key()


def test_store_rejects_unsafe_home(app_home: Path, tmp_path: Path) -> None:
    app_home.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(CredentialError, match="not a regular directory"):
        store_api_key("secret")


def test_store_rejects_symlinked_target(app_home: Path, tmp_path: Path) -> None:
    app_home.mkdir()
    (app_home / "vulners.key").symlink_to(tmp_path / "target")
    with pytest.raises(CredentialError, match="symlinked"):
        store_api_key("secret")


def test_store_wraps_and_cleans_up_os_errors(
    monkeypatch: pytest.MonkeyPatch, app_home: Path
) -> None:
    def fail(*_args: object, **_kwargs: object) -> tuple[int, str]:
        raise OSError("disk full")

    monkeypatch.setattr(tempfile, "mkstemp", fail)
    with pytest.raises(CredentialError, match="disk full"):
        store_api_key("secret")


def test_store_removes_temporary_file_after_replace_error(
    monkeypatch: pytest.MonkeyPatch, app_home: Path
) -> None:
    def fail(_source: Path, _target: Path) -> Path:
        raise OSError("replace failed")

    monkeypatch.setattr(Path, "replace", fail)
    with pytest.raises(CredentialError, match="replace failed"):
        store_api_key("secret")
    assert list(app_home.iterdir()) == []


def test_store_closes_descriptor_after_permission_error(
    monkeypatch: pytest.MonkeyPatch, app_home: Path
) -> None:
    descriptors: list[int] = []
    real_mkstemp = tempfile.mkstemp

    def track_descriptor(
        *,
        prefix: str,
        dir: Path,  # noqa: A002 - match tempfile.mkstemp's keyword API.
    ) -> tuple[int, str]:
        descriptor, name = real_mkstemp(prefix=prefix, dir=dir)
        descriptors.append(descriptor)
        return descriptor, name

    def fail_permissions(*_args: object, **_kwargs: object) -> None:
        raise OSError("permissions failed")

    monkeypatch.setattr(credentials, "_WINDOWS", False)
    monkeypatch.setattr(tempfile, "mkstemp", track_descriptor)
    monkeypatch.setattr(os, "fchmod", fail_permissions)

    with pytest.raises(CredentialError, match="permissions failed"):
        store_api_key("secret")
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
    assert list(app_home.iterdir()) == []


def test_load_wraps_read_errors(monkeypatch: pytest.MonkeyPatch, app_home: Path) -> None:
    app_home.mkdir()
    path = app_home / "vulners.key"
    path.write_text("secret")

    def fail(*_args: object, **_kwargs: object) -> int:
        raise OSError("denied")

    monkeypatch.setattr(os, "open", fail)
    with pytest.raises(CredentialError, match="denied"):
        load_api_key()


def test_load_skips_posix_permission_migration_on_windows(
    monkeypatch: pytest.MonkeyPatch, app_home: Path
) -> None:
    app_home.mkdir()
    (app_home / "vulners.key").write_text("secret")
    monkeypatch.setattr(credentials, "_WINDOWS", True)

    def fail(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("fchmod must not be called on Windows")

    monkeypatch.setattr(os, "fchmod", fail)
    assert load_api_key() == "secret"
