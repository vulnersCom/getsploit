from __future__ import annotations

from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from rich.console import Console
from rich.progress import Task as ProgressTask
from rich.text import Text

from getsploit.models import DatabaseStatus, Exploit
from getsploit.output import (
    _AmountColumn,
    _RateColumn,
    install_progress,
    render_results,
    render_status,
    serialize_results,
    terminal_safe,
)


def progress_task(**overrides: Any) -> ProgressTask:
    """A stand-in exposing only the attributes the progress columns read."""
    defaults: dict[str, Any] = {"fields": {}, "total": None, "completed": 0, "speed": None}
    return cast(ProgressTask, SimpleNamespace(**{**defaults, **overrides}))


def console_output(
    *, terminal: bool, color: bool = True, width: int = 120
) -> tuple[Console, StringIO]:
    stream = StringIO()
    console = Console(
        file=stream,
        force_terminal=terminal,
        color_system="standard" if terminal and color else None,
        width=width,
        legacy_windows=False,
        _environ={"COLUMNS": str(width), "LINES": "24"},
    )
    return console, stream


def test_serializers(exploit: Exploit) -> None:
    assert '"id": "EDB-ID:42"' in serialize_results([exploit], "json")
    assert serialize_results([exploit], "jsonl").count("\n") == 0
    assert serialize_results([], "jsonl") == ""
    with pytest.raises(ValueError, match="Unsupported output format"):
        serialize_results([], "xml")


def test_non_terminal_output_is_stable_plain_text(exploit: Exploit) -> None:
    console, stream = console_output(terminal=False)
    render_results(console, [exploit], "https://example/search")
    assert "EDB-ID:42\tExample exploit\thttps://" in stream.getvalue()


def test_narrow_terminal_uses_compact_records(exploit: Exploit) -> None:
    console, stream = console_output(terminal=True, width=70)
    render_results(console, [exploit], "https://example/search")
    assert "Example exploit" in stream.getvalue()
    assert "╭" not in stream.getvalue()


def test_wide_terminal_uses_table(exploit: Exploit) -> None:
    console, stream = console_output(terminal=True)
    render_results(console, [exploit], "https://example/search")
    assert "╭" in stream.getvalue()


def test_colorless_terminal_still_uses_adaptive_table(exploit: Exploit) -> None:
    console, stream = console_output(terminal=True, color=False)
    render_results(console, [exploit], "https://example/search")
    assert "╭" in stream.getvalue()
    assert "\x1b[" not in stream.getvalue()


def test_empty_result_stops_after_summary() -> None:
    console, stream = console_output(terminal=True)
    render_results(console, [], "https://example/search")
    assert "Found: 0" in Text.from_ansi(stream.getvalue()).plain
    assert "╭" not in stream.getvalue()


def test_database_status_renders_optional_timestamp(tmp_path: Path) -> None:
    console, stream = console_output(terminal=False)
    render_status(
        console,
        DatabaseStatus(tmp_path / "db", 1536, 1234, 1, "FTS5", "2026-01-01T00:00:00Z"),
    )
    output = stream.getvalue()
    assert "1,234" in output
    assert "1.5 kB" in output
    assert "Generated" in output


def test_database_status_omits_missing_timestamp(tmp_path: Path) -> None:
    console, stream = console_output(terminal=False)
    render_status(console, DatabaseStatus(tmp_path / "db", 1, 0, 0, "FTS4"))
    assert "Generated" not in stream.getvalue()


def test_database_status_replaces_terminal_controls(tmp_path: Path) -> None:
    console, stream = console_output(terminal=False)
    render_status(
        console,
        DatabaseStatus(
            tmp_path / "db\x1b]52;c;path\x07",
            1,
            0,
            1,
            "FTS5\x1b]52;c;index\x07",
            "2026-01-01\x1b00:00:00",
        ),
    )
    assert "\x1b" not in stream.getvalue()
    assert "\x07" not in stream.getvalue()


def test_plain_cells_replace_terminal_controls() -> None:
    assert terminal_safe("safe\n\x1b[31m") == "safe  [31m"


@pytest.mark.parametrize(
    ("task", "expected"),
    [
        (
            progress_task(fields={"unit": "documents"}, completed=1000, total=281358),
            "1,000/281,358 docs",
        ),
        (progress_task(fields={"unit": "documents"}, completed=0, total=None), "0/? docs"),
        (
            progress_task(fields={"unit": "bytes"}, completed=536870912, total=1073741824),
            "536.9 MB/1.1 GB",
        ),
        # A phase that declares no unit has no measurable size, whatever it has done.
        (progress_task(fields={"unit": ""}, completed=2048, total=None), ""),
        (progress_task(fields={"unit": ""}, completed=0, total=None), ""),
    ],
)
def test_amount_column_uses_the_task_unit(task: ProgressTask, expected: str) -> None:
    assert _AmountColumn().render(task).plain == expected


@pytest.mark.parametrize(
    ("task", "expected"),
    [
        (progress_task(speed=None), ""),
        (progress_task(fields={"unit": "documents"}, speed=18432.7), "18,433 docs/s"),
        (progress_task(fields={"unit": "bytes"}, speed=925800000), "925.8 MB/s"),
    ],
)
def test_rate_column_uses_the_task_unit(task: ProgressTask, expected: str) -> None:
    assert _RateColumn().render(task).plain == expected


def test_install_progress_renders_both_units() -> None:
    console, stream = console_output(terminal=True, width=110)
    with install_progress(console) as progress:
        documents = progress.add_task("Converting documents", total=281358, unit="documents")
        progress.update(documents, completed=1000)
        progress.refresh()
        archive = progress.add_task("Unpacking archive", total=1073741824, unit="bytes")
        progress.update(archive, completed=536870912)
        progress.refresh()
    output = stream.getvalue()
    assert "docs" in output
    assert "GB" in output
