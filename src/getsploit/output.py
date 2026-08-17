from __future__ import annotations

import json
from collections.abc import Sequence

from rich import box, filesize
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.progress import Task as ProgressTask
from rich.table import Table
from rich.text import Text

from .models import BYTES, DOCUMENTS, DatabaseStatus, Exploit

# Three folded columns need roughly this much room before a table beats stacked records:
# below it the ID and URL columns wrap on nearly every row.
_MIN_TABLE_WIDTH = 96


class _AmountColumn(ProgressColumn):
    """Render completion in the task's own unit.

    Rich's DownloadColumn formats every task as bytes, which turned 281,358 documents
    into "281.4 kB".
    """

    def render(self, task: ProgressTask) -> Text:
        # Dispatch on the unit alone: a phase that declares no unit has no measurable
        # size, and printing a number for it would be a number the phase cannot know.
        unit = task.fields.get("unit")
        if unit == DOCUMENTS:
            total = f"{int(task.total):,}" if task.total else "?"
            return Text(f"{int(task.completed):,}/{total} docs", style="progress.download")
        if unit == BYTES:
            done = filesize.decimal(int(task.completed))
            total = filesize.decimal(int(task.total)) if task.total else "?"
            return Text(f"{done}/{total}", style="progress.download")
        return Text("", style="progress.download")


class _RateColumn(ProgressColumn):
    """Render throughput in the task's own unit, blank until a rate is known."""

    def render(self, task: ProgressTask) -> Text:
        if task.speed is None:
            return Text("", style="progress.data.speed")
        if task.fields.get("unit") == DOCUMENTS:
            return Text(f"{task.speed:,.0f} docs/s", style="progress.data.speed")
        return Text(f"{filesize.decimal(int(task.speed))}/s", style="progress.data.speed")


def install_progress(console: Console) -> Progress:
    """Progress display for the phases of `--update`."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        _AmountColumn(),
        _RateColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=True,
    )


def serialize_results(exploits: Sequence[Exploit], output_format: str) -> str:
    rows = [
        {"id": exploit.id, "title": exploit.title, "url": exploit.url} for exploit in exploits
    ]
    if output_format == "json":
        return json.dumps(rows, ensure_ascii=False, indent=2)
    if output_format == "jsonl":
        return "\n".join(json.dumps(row, ensure_ascii=False) for row in rows)
    raise ValueError(f"Unsupported output format: {output_format}")


def terminal_safe(value: str) -> str:
    return "".join(character if character.isprintable() else " " for character in value)


def _safe_rows(exploits: Sequence[Exploit]) -> list[tuple[str, str, str]]:
    """Sanitize every result field once, so no renderer below can forget to."""
    return [
        (terminal_safe(exploit.id), terminal_safe(exploit.title), terminal_safe(exploit.url))
        for exploit in exploits
    ]


def render_results(
    console: Console,
    exploits: Sequence[Exploit],
    search_url: str,
) -> None:
    console.print(Text.assemble(("Found:", "bold"), f" {len(exploits)}"))
    # soft_wrap keeps the URL on one logical line. Rich would otherwise fold it at the
    # console width, and a URL split across lines cannot be copied or clicked.
    console.print(Text.assemble(("Web search:", "dim"), f" {search_url}"), soft_wrap=True)
    if not exploits:
        return
    rows = _safe_rows(exploits)
    if not console.is_terminal:
        for exploit_id, title, url in rows:
            console.file.write(f"{exploit_id}\t{title}\t{url}\n")
        console.file.flush()
        return
    if console.width < _MIN_TABLE_WIDTH:
        for exploit_id, title, url in rows:
            line = Text()
            line.append(exploit_id, style="bold cyan")
            line.append("  ")
            line.append(title)
            console.print(line)
            console.print(f"  {url}", markup=False, highlight=False, soft_wrap=True)
        return

    table = Table(box=box.ROUNDED, expand=True, show_lines=True)
    # Identifiers and URLs are the actionable fields, and both exceed any sensible
    # column width (EXPLOITPACK ids reach 44 characters, their URLs 76). Folding wraps
    # them onto another line; the default ellipsis overflow would discard the tail.
    table.add_column("ID", style="bold cyan", ratio=3, overflow="fold")
    # Titles carry proof-of-concept URLs and long request paths, which do not break
    # across lines, so they need folding for the same reason.
    table.add_column("Title", ratio=5, overflow="fold")
    table.add_column("URL", style="blue", ratio=5, overflow="fold")
    for exploit_id, title, url in rows:
        table.add_row(Text(exploit_id), Text(title), Text(url))
    console.print(table)


def render_status(console: Console, status: DatabaseStatus) -> None:
    rows = [
        ("Database", str(status.path)),
        ("Index", status.index),
        ("Schema", str(status.schema_version)),
        ("Documents", f"{status.documents:,}"),
        # The same formatter as the progress bars: a database reported as "1.5 GiB"
        # here and "1.7 GB" while unpacking reads as two different databases.
        ("Size", filesize.decimal(status.size)),
    ]
    if status.generated_at:
        rows.append(("Generated", status.generated_at))
    # Plain aligned lines rather than a grid: soft_wrap keeps the database path on one
    # logical line, where a table column would fold it and bury spaces inside the path.
    label_width = max(len(label) for label, _ in rows)
    for label, value in rows:
        console.print(
            Text.assemble((f"{label:<{label_width}}", "bold"), f"  {terminal_safe(value)}"),
            soft_wrap=True,
        )
