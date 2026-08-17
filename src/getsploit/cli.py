from __future__ import annotations

import asyncio
import contextlib
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import click
from rich.console import Console
from rich.progress import Progress, TaskID

from .credentials import CredentialError, load_api_key, store_api_key
from .database import DatabaseError, ExploitDatabase
from .files import MirrorError, mirror_exploits
from .models import ProgressCallback
from .output import (
    install_progress,
    render_results,
    render_status,
    serialize_results,
    terminal_safe,
)
from .vulners import (
    VulnersAdapterError,
    download_database_archive,
    search_exploits,
    web_search_url,
)

_FALLBACK_WIDTH = 80


@dataclass(frozen=True, slots=True)
class SearchRequest:
    query: str
    count: int
    local: bool
    api_key: str | None
    output_format: str
    mirror: bool


def _console(color: str) -> Console:
    stream = click.get_text_stream("stdout", errors="replace")
    if color == "always":
        console = Console(file=stream, force_terminal=True)
    elif color == "never":
        console = Console(file=stream, force_terminal=stream.isatty(), color_system=None)
    else:
        console = Console(file=stream)
    if console.width <= 0:
        # An empty, zero or non-numeric COLUMNS makes Rich report width 0, and a
        # zero-width console renders nothing at all: no results, no error, exit 0.
        console.width = _FALLBACK_WIDTH
    return console


def _phase_reporter(progress: Progress) -> ProgressCallback:
    """Bridge one operation's phase reports onto the progress display.

    Each phase gets its own task, replacing the previous one from the same operation. A
    phase whose size becomes known only later, such as a download, is served by passing
    the total on every update: Rich reads `total=None` as "leave unchanged", which is
    exactly right for a step that has no measurable size at all.
    """
    task: TaskID | None = None
    phase = ""

    def report(current_phase: str, completed: int, total: int | None, unit: str) -> None:
        nonlocal task, phase
        if current_phase != phase:
            if task is not None:
                progress.remove_task(task)
            task = progress.add_task(current_phase, total=total, unit=unit)
            phase = current_phase
        progress.update(cast("TaskID", task), completed=completed, total=total)

    return report


async def _update_database(console: Console, api_key: str | None) -> None:
    database = ExploitDatabase()
    with tempfile.TemporaryDirectory(prefix="getsploit-") as temporary_directory:
        archive = Path(temporary_directory) / "getsploit.db.zip"
        with install_progress(console) as progress:
            # A reporter per operation, so the finished download stays on screen while
            # installation reports its own phases.
            await download_database_archive(archive, api_key, progress=_phase_reporter(progress))
            status = await asyncio.to_thread(
                database.install_archive, archive, _phase_reporter(progress)
            )
    console.print("[bold green]Database updated.[/]")
    render_status(console, status)


async def _search(console: Console, request: SearchRequest) -> None:
    # The table format is the only human-facing one; the machine formats carry data
    # alone, so status messages and decoration must stay out of their stream.
    human_output = request.output_format == "table"

    if request.local:
        exploits = await asyncio.to_thread(ExploitDatabase().search, request.query, request.count)
    else:
        searching = (
            console.status("Searching Vulners...") if human_output else contextlib.nullcontext()
        )
        with searching:
            exploits = await search_exploits(request.query, request.count, request.api_key)

    if human_output:
        render_results(console, exploits, web_search_url(request.query))
    else:
        click.echo(serialize_results(exploits, request.output_format))

    if request.mirror:
        directory = await asyncio.to_thread(mirror_exploits, exploits, request.query)
        # No results means no directory was created, so naming one would mislead.
        message = (
            f"Saved {len(exploits)} files to {directory}" if exploits else "No exploits to save."
        )
        if human_output:
            # soft_wrap keeps the path on one logical line so it stays copyable.
            console.print(f"[green]{message}[/]", soft_wrap=True)
        else:
            click.echo(message, err=True)


_MISSING_KEY = (
    "No Vulners API key found. Set VULNERS_API_KEY or run 'getsploit --set-key'. "
    "Create a key at https://vulners.com/userinfo"
)


def _validate_mode(update: bool, status: bool, set_key: bool, query: tuple[str, ...]) -> None:
    actions = sum((update, status, set_key))
    if actions > 1:
        raise click.UsageError("Use only one of --update, --status, or --set-key.")
    if (update or status) and query:
        raise click.UsageError("Search terms cannot be combined with --update or --status.")
    if set_key and query:
        raise click.UsageError("--set-key reads the key from a hidden prompt.")
    # Strip before deciding: the SDK raises a bare ValueError on a blank query, which
    # would escape as a traceback rather than a usage error.
    if not any((update, status, set_key)) and not " ".join(query).strip():
        raise click.UsageError("Search query is required.")


@click.command("getsploit", context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(package_name="getsploit")
@click.option("-j", "--json", "json_output", is_flag=True, help="Alias for --format json.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(("table", "json", "jsonl"), case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--color",
    type=click.Choice(("auto", "always", "never"), case_sensitive=False),
    default="auto",
    show_default=True,
    help="Color mode for terminal output.",
)
@click.option("-m", "--mirror", is_flag=True, help="Save exploit source files locally.")
@click.option("-l", "--local", is_flag=True, help="Search the local database.")
@click.option("-u", "--update", is_flag=True, help="Download and rebuild the local database.")
@click.option("--status", is_flag=True, help="Show local database details.")
@click.option("-s", "--set-key", is_flag=True, help="Store the API key in the legacy key file.")
@click.option("-c", "--count", type=click.IntRange(1, 1000), default=10, show_default=True)
@click.argument("query", nargs=-1)
def main(  # noqa: PLR0913, PLR0917 - Click injects one argument per declared option.
    json_output: bool,
    output_format: str,
    color: str,
    mirror: bool,
    local: bool,
    update: bool,
    status: bool,
    set_key: bool,
    count: int,
    query: tuple[str, ...],
) -> None:
    """Search and download public exploits from Vulners."""
    _validate_mode(update, status, set_key, query)
    if json_output:
        if output_format != "table":
            raise click.UsageError("Use either --json or --format, not both.")
        output_format = "json"

    console = _console(color)
    query_value = " ".join(query)
    try:
        if set_key:
            store_api_key(
                click.prompt("Vulners API key", hide_input=True, confirmation_prompt=True)
            )
            console.print("[green]API key stored.[/]")
        elif status:
            render_status(console, ExploitDatabase().status())
        else:
            key = load_api_key()
            if key is None and (update or not local):
                raise click.ClickException(_MISSING_KEY)
            if update:
                asyncio.run(_update_database(console, key))
            else:
                request = SearchRequest(
                    query=query_value,
                    count=count,
                    local=local,
                    api_key=key,
                    output_format=output_format,
                    mirror=mirror,
                )
                asyncio.run(_search(console, request))
    except (CredentialError, DatabaseError, MirrorError, VulnersAdapterError) as error:
        raise click.ClickException(terminal_safe(str(error))) from error


if __name__ == "__main__":
    main()
