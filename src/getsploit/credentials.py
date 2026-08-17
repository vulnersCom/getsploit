from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from pathlib import Path

from .paths import api_key_path, home_path

_WINDOWS = os.name == "nt"


class CredentialError(Exception):
    """Raised when the legacy API-key file cannot be used safely."""


def load_api_key() -> str | None:
    environment_key = os.environ.get("VULNERS_API_KEY", "").strip()
    if environment_key:
        return environment_key
    path = api_key_path()
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink():
        raise CredentialError(f"API-key path is not a regular file: {path}")
    try:
        # O_NONBLOCK so a FIFO left at this path cannot block the open forever: the
        # regular-file check below runs on the descriptor and is only reachable if the
        # open returns. It has no effect on reads from a regular file.
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(path, flags)
        except PermissionError as error:
            # Windows refuses to open a directory at all, where POSIX opens it and lets
            # the check below reject it. Report the same cause on both.
            if path.is_dir():
                raise CredentialError(f"API-key path is not a regular file: {path}") from error
            raise
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise CredentialError(f"API-key path is not a regular file: {path}")
            if not _WINDOWS:
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, encoding="utf-8") as source:
                descriptor = -1
                return source.read().strip() or None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except CredentialError:
        raise
    except UnicodeDecodeError as error:
        # PowerShell's `>` writes UTF-16, so a hand-made key file is a realistic input.
        raise CredentialError(f"API-key file is not valid UTF-8 text: {path}") from error
    except OSError as error:
        raise CredentialError(f"Cannot read API key: {error}") from error


def store_api_key(api_key: str) -> None:
    directory = home_path()
    target = api_key_path()
    temporary: Path | None = None
    try:
        if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
            raise CredentialError(f"Getsploit home is not a regular directory: {directory}")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not _WINDOWS:
            directory.chmod(0o700)
        if target.is_symlink():
            raise CredentialError(f"Refusing to replace symlinked API-key path: {target}")

        descriptor, name = tempfile.mkstemp(prefix=".vulners.key.", dir=directory)
        temporary = Path(name)
        try:
            if not _WINDOWS:
                os.fchmod(descriptor, 0o600)
            output = os.fdopen(descriptor, "w", encoding="utf-8")
            descriptor = -1
            with output:
                output.write(api_key)
                output.flush()
                os.fsync(output.fileno())
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        temporary.replace(target)
        temporary = None
    except CredentialError:
        raise
    except OSError as error:
        raise CredentialError(f"Cannot store API key: {error}") from error
    finally:
        if temporary is not None:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()
