from __future__ import annotations

from pathlib import Path

import pytest

from getsploit.files import MirrorError, mirror_exploits
from getsploit.models import Exploit


def test_mirror_writes_safe_utf8_files(tmp_path: Path, exploit: Exploit) -> None:
    fallback = Exploit("PACKET/STORM:7", "fallback", "url", description="payload")

    directory = mirror_exploits([exploit, fallback], "WördPress 4.7!", tmp_path)

    assert directory == tmp_path / "wordpress-4.7"
    assert (directory / "edb-id-42.txt").read_text() == "print('source')"
    assert (directory / "packet-storm-7.txt").read_text() == "payload"


def test_mirror_uses_fallback_names(tmp_path: Path) -> None:
    directory = mirror_exploits([Exploit("???", "title", "url")], "你好", tmp_path)
    assert directory == tmp_path / "exploits"
    assert (directory / "exploit.txt").is_file()


def test_mirror_rejects_duplicate_safe_names(tmp_path: Path) -> None:
    exploits = [Exploit("A:B", "one", "url"), Exploit("A/B", "two", "url")]
    with pytest.raises(MirrorError, match="Duplicate exploit filename"):
        mirror_exploits(exploits, "query", tmp_path)
    assert not (tmp_path / "query" / "a-b.txt").exists()


def test_mirror_wraps_filesystem_errors(tmp_path: Path) -> None:
    target = tmp_path / "query"
    (target / "id.txt").mkdir(parents=True)
    with pytest.raises(MirrorError, match="Cannot write exploit ID"):
        mirror_exploits([Exploit("ID", "title", "url")], "query", tmp_path)


def test_mirror_rejects_symlinked_directory(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "query").symlink_to(target, target_is_directory=True)
    with pytest.raises(MirrorError, match="not a regular directory"):
        mirror_exploits([], "query", tmp_path)


def test_mirror_wraps_directory_creation_error(tmp_path: Path) -> None:
    destination = tmp_path / "file"
    destination.write_text("not a directory")
    with pytest.raises(MirrorError, match="Cannot create mirror directory"):
        mirror_exploits([Exploit("ID", "title", "url")], "query", destination)


def test_mirror_without_results_creates_no_directory(tmp_path: Path) -> None:
    directory = mirror_exploits([], "query", tmp_path)

    assert directory == tmp_path / "query"
    assert not directory.exists()


def test_mirror_truncates_absurdly_long_names(tmp_path: Path) -> None:
    """A 400-character id used to abort the whole run with `File name too long`."""
    exploit = Exploit("A" * 400, "long id", "url", source_data="body")

    directory = mirror_exploits([exploit], "Q" * 400, tmp_path)

    written = list(directory.iterdir())
    assert len(directory.name) <= 200
    assert [path.read_text() for path in written] == ["body"]
    assert len(written[0].name) <= 204


def test_mirror_leaves_no_directory_when_the_plan_is_rejected(tmp_path: Path) -> None:
    exploits = [Exploit("A:B", "one", "url"), Exploit("A/B", "two", "url")]

    with pytest.raises(MirrorError, match="Duplicate exploit filename"):
        mirror_exploits(exploits, "query", tmp_path)

    assert not (tmp_path / "query").exists()
