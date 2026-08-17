from __future__ import annotations

import asyncio
import json
import os
import runpy
import sqlite3
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest
from click.testing import CliRunner
from rich.console import Console

from getsploit import cli
from getsploit.database import ExploitDatabase
from getsploit.files import MirrorError
from getsploit.models import Exploit, ProgressCallback
from getsploit.output import install_progress
from getsploit.vulners import VulnersAdapterError


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def app_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    home = tmp_path / "home"
    monkeypatch.setenv("GETSPLOIT_HOME", str(home))
    return home


def test_help_and_version(runner: CliRunner) -> None:
    help_result = runner.invoke(cli.main, ["--help"])
    version_result = runner.invoke(cli.main, ["--version"])
    assert help_result.exit_code == 0
    assert "Search and download public exploits" in help_result.output
    assert "--api-key" not in help_result.output
    assert version_result.exit_code == 0
    assert "getsploit" in version_result.output


def test_module_entrypoint(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def fake_main() -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(cli, "main", fake_main)
    runpy.run_module("getsploit.__main__", run_name="__main__")
    assert called


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        ([], "Search query is required"),
        (["--update", "--status"], "Use only one"),
        (["--update", "query"], "cannot be combined"),
        (["--status", "query"], "cannot be combined"),
        (["--set-key", "secret"], "hidden prompt"),
        (["--json", "--format", "jsonl", "query"], "either --json or --format"),
    ],
)
def test_invalid_modes(runner: CliRunner, arguments: list[str], message: str) -> None:
    result = runner.invoke(cli.main, arguments)
    assert result.exit_code == 2
    assert message in result.output


def test_set_key_uses_private_legacy_file(runner: CliRunner, app_home: Path) -> None:
    result = runner.invoke(
        cli.main,
        ["--color", "never", "--set-key"],
        input="secret\nsecret\n",
    )
    key_path = app_home / "vulners.key"
    assert result.exit_code == 0
    assert key_path.read_text() == "secret"
    if os.name != "nt":
        assert key_path.stat().st_mode & 0o777 == 0o600


def test_online_search_formats_and_mirrors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    exploit = Exploit("ID", "Title", "https://example", source_data="payload")

    async def fake_search(query: str, count: int, credential: str | None) -> list[Exploit]:
        assert query in {"query", "table-query", "jsonl-query"}
        assert credential == "key"
        assert count in (3, 10)
        return [exploit]

    monkeypatch.setattr(cli, "search_exploits", fake_search)
    monkeypatch.setenv("VULNERS_API_KEY", "key")
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()

    table = runner.invoke(cli.main, ["--count", "3", "query"])
    table_mirror = runner.invoke(cli.main, ["--mirror", "table-query"])
    json_result = runner.invoke(cli.main, ["--json", "query"])
    jsonl = runner.invoke(
        cli.main,
        ["--format", "jsonl", "--mirror", "jsonl-query"],
    )

    assert table.exit_code == 0
    assert "ID\tTitle\thttps://example" in table.output
    assert table_mirror.exit_code == 0
    assert "Saved 1 files" in table_mirror.output
    assert json_result.exit_code == 0
    assert json.loads(json_result.stdout) == [
        {"id": "ID", "title": "Title", "url": "https://example"}
    ]
    assert json_result.stderr == ""
    assert jsonl.exit_code == 0
    assert [json.loads(line) for line in jsonl.stdout.splitlines()] == [
        {"id": "ID", "title": "Title", "url": "https://example"}
    ]
    assert "\x1b" not in json_result.stdout + jsonl.stdout
    assert "Saved 1 files" not in jsonl.stdout
    assert "Saved 1 files" in jsonl.stderr
    assert (tmp_path / "jsonl-query" / "id.txt").read_text() == "payload"


def test_local_search_uses_real_fts5_database(
    runner: CliRunner, app_home: Path, legacy_archive: Path
) -> None:
    ExploitDatabase().install_archive(legacy_archive)
    result = runner.invoke(cli.main, ["--local", "--color", "never", "WordPress"])
    assert result.exit_code == 0
    assert "EDB-ID:42" in result.output


def test_ascii_locale_uses_utf8_stdout(app_home: Path, legacy_archive: Path) -> None:
    database = ExploitDatabase()
    database.install_archive(legacy_archive)
    with sqlite3.connect(database.path) as connection:
        connection.execute(
            "UPDATE exploits SET title = 'WordPress café exploit' WHERE id = 'EDB-ID:42'"
        )

    environment = os.environ.copy()
    environment.update(
        GETSPLOIT_HOME=str(app_home),
        LANG="C",
        LC_ALL="C",
        PYTHONUTF8="0",
        PYTHONCOERCECLOCALE="0",
    )
    result = subprocess.run(
        [sys.executable, "-m", "getsploit", "--local", "WordPress"],
        capture_output=True,
        env=environment,
        check=False,
    )

    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert "WordPress café exploit" in result.stdout.decode("utf-8")


def test_update_and_status(
    monkeypatch: pytest.MonkeyPatch,
    runner: CliRunner,
    app_home: Path,
    legacy_archive: Path,
) -> None:
    destinations: list[Path] = []
    archive_data = legacy_archive.read_bytes()

    async def fake_download(
        destination: Path, credential: str | None, *, progress: ProgressCallback
    ) -> int:
        assert credential == "key"
        destinations.append(destination)
        written = await asyncio.to_thread(destination.write_bytes, archive_data)
        # The adapter reports the download itself, through the same callback the
        # installer uses; only its bytes-per-phase reporting lives in the adapter.
        progress("Downloading archive", written, written, "bytes")
        return written

    monkeypatch.setattr(cli, "download_database_archive", fake_download)
    monkeypatch.setenv("VULNERS_API_KEY", "key")
    update = runner.invoke(cli.main, ["--color", "never", "--update"])
    status = runner.invoke(cli.main, ["--color", "never", "--status"])
    assert update.exit_code == 0
    assert "Database updated" in update.output
    assert (app_home / "getsploit.db").is_file()
    assert not destinations[0].exists()
    assert status.exit_code == 0
    assert "FTS5" in status.output


def test_database_errors_become_click_errors(runner: CliRunner, app_home: Path) -> None:
    result = runner.invoke(cli.main, ["--local", "query"])
    assert result.exit_code == 1
    assert "Local database not found" in result.output


def test_missing_api_key_names_both_ways_to_supply_one(runner: CliRunner) -> None:
    result = runner.invoke(cli.main, ["query"])

    assert result.exit_code == 1
    assert "VULNERS_API_KEY" in result.output
    assert "--set-key" in result.output
    # The SDK's own wording suggests an api_key= argument the CLI does not accept.
    assert "api_key=" not in result.output


def test_vulners_errors_become_click_errors(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    async def fail(*_args: object, **_kwargs: object) -> list[Exploit]:
        raise VulnersAdapterError("API failed\x1b]52;c;payload\x07")

    monkeypatch.setenv("VULNERS_API_KEY", "key")
    monkeypatch.setattr(cli, "search_exploits", fail)
    result = runner.invoke(cli.main, ["query"])
    assert result.exit_code == 1
    assert "API failed" in result.output
    assert "\x1b" not in result.output
    assert "\x07" not in result.output


def test_mirror_errors_become_click_errors(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    async def fake_search(*_args: object, **_kwargs: object) -> list[Exploit]:
        return []

    def fail(*_args: object, **_kwargs: object) -> Path:
        raise MirrorError("mirror failed")

    monkeypatch.setenv("VULNERS_API_KEY", "key")
    monkeypatch.setattr(cli, "search_exploits", fake_search)
    monkeypatch.setattr(cli, "mirror_exploits", fail)
    result = runner.invoke(cli.main, ["--mirror", "query"])
    assert result.exit_code == 1
    assert "mirror failed" in result.output


def test_mirror_without_results_names_no_directory(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner, tmp_path: Path
) -> None:
    async def empty_search(*_args: object, **_kwargs: object) -> list[Exploit]:
        return []

    monkeypatch.setenv("VULNERS_API_KEY", "key")
    monkeypatch.setattr(cli, "search_exploits", empty_search)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli.main, ["--mirror", "query"])

    assert result.exit_code == 0
    assert "No exploits to save." in result.output
    assert not (tmp_path / "query").exists()


def test_zero_width_terminal_still_renders_results(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner, exploit: Exploit
) -> None:
    """An empty or zero COLUMNS made Rich report width 0 and print nothing at all."""

    async def fake_search(*_args: object, **_kwargs: object) -> list[Exploit]:
        return [exploit]

    monkeypatch.setenv("VULNERS_API_KEY", "key")
    monkeypatch.setenv("COLUMNS", "0")
    monkeypatch.setattr(cli, "search_exploits", fake_search)

    result = runner.invoke(cli.main, ["--color", "always", "query"])

    assert result.exit_code == 0
    assert "EDB-ID:42" in result.output


@pytest.mark.parametrize("color", ["auto", "always", "never"])
def test_color_modes(runner: CliRunner, app_home: Path, color: str) -> None:
    result = runner.invoke(
        cli.main,
        ["--color", color, "--set-key"],
        input="secret\nsecret\n",
    )
    assert result.exit_code == 0


def test_each_operation_reports_its_phases_on_its_own_task() -> None:
    """A finished download stays on screen while installation reports its own phases."""
    console = Console(file=StringIO(), force_terminal=True, width=100)
    with install_progress(console) as progress:
        download = cli._phase_reporter(progress)
        install = cli._phase_reporter(progress)
        download("Downloading archive", 0, None, "bytes")
        download("Downloading archive", 512, 512, "bytes")  # the total arrives late
        install("Unpacking archive", 10, 100, "bytes")
        install("Converting documents", 5, 50, "documents")

        assert [(task.description, task.completed, task.total) for task in progress.tasks] == [
            ("Downloading archive", 512, 512),
            ("Converting documents", 5, 50),
        ]
