from __future__ import annotations

import asyncio
import contextlib
import json
import stat
import urllib.parse
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from vulners import AsyncVulners, VulnersError

from ._limits import MAX_ARCHIVE_BYTES
from .models import BYTES, Exploit, ProgressCallback, discard_progress

_SEARCH_FIELDS = (
    "id",
    "type",
    "title",
    "description",
    "sourceData",
    "published",
    "vhref",
    "href",
)
_MAX_SEARCH_RESPONSE_BYTES = 32 * 1024**2
# The search endpoint returns no more than 100 documents per request.
_PAGE_SIZE = 100
_DOWNLOAD_PHASE = "Downloading archive"
# Fast enough to look live, slow enough not to stat the directory in a tight loop.
_POLL_SECONDS = 0.25
# st_blocks is reported in 512-byte units by POSIX convention.
_BLOCK_BYTES = 512


class VulnersAdapterError(Exception):
    """Raised when the Vulners SDK cannot complete an operation."""


def _text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def exploit_from_bulletin(bulletin: Any) -> Exploit:
    exploit_id = _text(getattr(bulletin, "id", None))
    collection = _text(getattr(bulletin, "type", None))
    url = _text(getattr(bulletin, "vhref", None) or getattr(bulletin, "href", None))
    if not url and collection and exploit_id:
        url = f"https://vulners.com/{collection}/{exploit_id}"
    return Exploit(
        id=exploit_id,
        title=_text(getattr(bulletin, "title", None)),
        url=url,
        published=_text(getattr(bulletin, "published", None)),
        description=_text(getattr(bulletin, "description", None)),
        source_data=_text(
            getattr(bulletin, "source_data", None) or getattr(bulletin, "sourceData", None)
        ),
        collection=collection,
    )


@asynccontextmanager
async def _session(
    api_key: str | None, client: AsyncVulners | None, max_response_bytes: int
) -> AsyncIterator[AsyncVulners]:
    """Yield the caller's client, or one owned for the duration of the call."""
    if client is not None:
        yield client
    else:
        async with AsyncVulners(api_key, max_response_bytes=max_response_bytes) as owned:
            yield owned


async def _search_pages(client: AsyncVulners, query: str, limit: int) -> list[Exploit]:
    """Collect up to `limit` exploits, following pages as needed.

    The API returns at most `_PAGE_SIZE` documents per request, so a single call
    silently delivered 100 results for any larger `--count`. Offsets are advanced by
    the number of rows actually received: `AsyncSearchPage.next_page` steps by the
    requested limit instead, which would skip results whenever a page comes back short.
    """
    exploits: list[Exploit] = []
    offset = 0
    while len(exploits) < limit:
        wanted = min(_PAGE_SIZE, limit - len(exploits))
        page = await client.search.exploits(
            query, limit=wanted, offset=offset, fields=_SEARCH_FIELDS
        )
        rows = [exploit_from_bulletin(item) for item in page.data]
        exploits.extend(rows)
        if len(rows) < wanted:  # A short page means the results are exhausted.
            break
        offset += len(rows)
    return exploits


async def search_exploits(
    query: str,
    limit: int,
    api_key: str | None = None,
    *,
    client: AsyncVulners | None = None,
) -> list[Exploit]:
    try:
        async with _session(api_key, client, _MAX_SEARCH_RESPONSE_BYTES) as session:
            return await _search_pages(session, query, limit)
    except VulnersError as error:
        raise VulnersAdapterError(str(error)) from error


def _directory_usage(directory: Path) -> tuple[int, int]:
    """Return (bytes on disk, bytes reserved) across the regular files in `directory`."""
    allocated = reserved = 0
    try:
        entries = list(directory.iterdir())
    except OSError:
        # Watching must never be able to fail a download. Nothing readable, nothing
        # to report, and no total can be adopted from a pair of zeroes.
        return 0, 0
    for entry in entries:
        # Entries come and go while the download commits, so a vanished one is normal.
        with contextlib.suppress(OSError):
            details = entry.stat()
            if not stat.S_ISREG(details.st_mode):
                continue
            reserved += details.st_size
            # Windows exposes no st_blocks, so there both values are the same and the
            # total simply stays unknown.
            blocks = getattr(details, "st_blocks", None)
            allocated += details.st_size if blocks is None else blocks * _BLOCK_BYTES
    return allocated, reserved


async def _follow_directory(report: ProgressCallback, directory: Path) -> None:
    """Report download progress by watching the directory the SDK writes into.

    The SDK probes the storage with a one-byte range request, reads the archive length
    from Content-Range and reserves that length on disk before filling ranges in
    parallel, so the reserved size is the real total while the allocated blocks are what
    has arrived. A reserved size that has stopped growing while data still arrives is
    therefore the total; a size that grows in step with the data means the single-stream
    fallback, which reserves nothing and has no knowable total.

    The SDK exposes neither a progress callback nor the length it read. Delete all of
    this the day it does, and report its numbers directly.
    """
    total: int | None = None
    settled = -1
    while True:
        allocated, reserved = _directory_usage(directory)
        if total is None and reserved == settled and allocated < reserved:
            total = reserved
        settled = reserved
        report(_DOWNLOAD_PHASE, min(allocated, total) if total else allocated, total, BYTES)
        await asyncio.sleep(_POLL_SECONDS)


async def _download_watched(
    client: AsyncVulners, destination: Path, connections: int, report: ProgressCallback
) -> int:
    report(_DOWNLOAD_PHASE, 0, None, BYTES)
    # Watching is unconditional: four stat calls a second cost nothing next to the
    # download, and one code path is easier to trust than two.
    follower = asyncio.create_task(_follow_directory(report, destination.parent))
    try:
        written = await client.archive.download_getsploit(destination, connections=connections)
    finally:
        follower.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await follower
    # The download reports exactly how many bytes it wrote, so the bar ends on 100%.
    report(_DOWNLOAD_PHASE, written, written, BYTES)
    return written


async def download_database_archive(
    destination: Path,
    api_key: str | None = None,
    *,
    connections: int = 8,
    progress: ProgressCallback | None = None,
    client: AsyncVulners | None = None,
) -> int:
    try:
        async with _session(api_key, client, MAX_ARCHIVE_BYTES) as session:
            return await _download_watched(
                session, destination, connections, progress or discard_progress
            )
    except (OSError, VulnersError) as error:
        raise VulnersAdapterError(f"Cannot download Vulners database archive: {error}") from error


def web_search_url(query: str) -> str:
    expression = f"bulletinFamily:exploit AND ({query})"
    return "https://vulners.com/search?query=" + urllib.parse.quote_plus(expression)
