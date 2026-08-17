from __future__ import annotations

import os
import re
import unicodedata
from collections.abc import Iterable
from pathlib import Path

from .models import Exploit

_UNSAFE_FILENAME = re.compile(r"[^a-zA-Z0-9._-]+")
# POSIX NAME_MAX is 255 bytes on ext4, APFS and NTFS. Names are ASCII by the time they
# are truncated, so 200 characters leaves room for the ".txt" suffix and for stacked
# filesystems with a lower limit. Third-party ids and queries are otherwise unbounded.
_MAX_NAME_LENGTH = 200


class MirrorError(Exception):
    """Raised when exploit files cannot be written safely."""


def _safe_name(value: str, fallback: str) -> str:
    ascii_value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    name = _UNSAFE_FILENAME.sub("-", ascii_value).strip(".-_").lower()
    # Strip again: truncation can expose a trailing separator.
    return name[:_MAX_NAME_LENGTH].strip(".-_") or fallback


def mirror_exploits(
    exploits: Iterable[Exploit], query: str, destination: Path | None = None
) -> Path:
    directory = (destination or Path.cwd()) / _safe_name(query, "exploits")
    if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
        raise MirrorError(f"Mirror path is not a regular directory: {directory}")

    # Plan before creating anything, so a search with no results and a rejected plan
    # both leave no empty directory behind.
    planned: list[tuple[Path, Exploit]] = []
    used_names: set[str] = set()
    for exploit in exploits:
        filename = _safe_name(exploit.id, "exploit")
        if filename in used_names:
            raise MirrorError(f"Duplicate exploit filename: {filename}")
        used_names.add(filename)
        planned.append((directory / f"{filename}.txt", exploit))
    if not planned:
        return directory

    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise MirrorError(f"Cannot create mirror directory: {error}") from error

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    for path, exploit in planned:
        try:
            descriptor = os.open(path, flags, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.write(exploit.content)
        except OSError as error:
            raise MirrorError(f"Cannot write exploit {exploit.id}: {error}") from error
    return directory
