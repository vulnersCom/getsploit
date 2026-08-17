from __future__ import annotations

import asyncio
import contextlib
import inspect
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from vulners import AsyncVulners, VulnersError

from getsploit import vulners as adapter


class FakeSearch:
    """Slices like the real endpoint, which never returns more than 100 documents."""

    def __init__(self, items: list[object]) -> None:
        self.items = items
        self.call: tuple[str, int, tuple[str, ...]] | None = None
        self.windows: list[tuple[int, int]] = []

    async def exploits(
        self, query: str, *, limit: int, fields: tuple[str, ...], offset: int = 0
    ) -> SimpleNamespace:
        self.call = query, limit, fields
        self.windows.append((offset, limit))
        return SimpleNamespace(data=self.items[offset : offset + limit])


class FakeArchive:
    def __init__(self) -> None:
        self.call: tuple[Path, int] | None = None

    async def download_getsploit(self, path: Path, *, connections: int) -> int:
        self.call = path, connections
        return await asyncio.to_thread(path.write_bytes, b"archive")


class FakeClient:
    def __init__(self, items: list[object] | None = None) -> None:
        self.search = FakeSearch(items or [])
        self.archive = FakeArchive()


def test_bulletin_mapping_prefers_vulners_url_and_serializes_extra_data() -> None:
    bulletin = SimpleNamespace(
        id="EDB-ID:42",
        type="exploitdb",
        title="title",
        vhref="https://vulners.com/exploitdb/EDB-ID:42",
        href="https://origin.example/42",
        published=None,
        description=None,
        source_data={"date": date(2026, 1, 2), "a": 1},
    )
    exploit = adapter.exploit_from_bulletin(bulletin)
    assert exploit.url == bulletin.vhref
    assert exploit.published == ""
    assert exploit.source_data == '{"a": 1, "date": "2026-01-02"}'


def test_bulletin_mapping_uses_origin_url() -> None:
    bulletin = SimpleNamespace(
        id="ID", type="source", title=None, href="https://origin", sourceData="raw"
    )
    exploit = adapter.exploit_from_bulletin(bulletin)
    assert exploit.url == "https://origin"
    assert exploit.title == ""
    assert exploit.source_data == "raw"


def test_bulletin_mapping_builds_missing_url() -> None:
    exploit = adapter.exploit_from_bulletin(SimpleNamespace(id="ID", type="source"))
    assert exploit.url == "https://vulners.com/source/ID"


def test_bulletin_mapping_keeps_url_empty_without_identity() -> None:
    exploit = adapter.exploit_from_bulletin(SimpleNamespace())
    assert exploit.url == ""


@pytest.mark.asyncio
async def test_search_uses_typed_sdk_resource() -> None:
    bulletin = SimpleNamespace(id="ID", type="source", title="title")
    client = FakeClient([bulletin])
    results = await adapter.search_exploits("query", 7, client=cast(Any, client))
    assert results[0].id == "ID"
    assert client.search.call is not None
    assert client.search.call[:2] == ("query", 7)
    assert "sourceData" in client.search.call[2]


@pytest.mark.asyncio
async def test_search_pages_past_the_hundred_document_response_limit() -> None:
    """A single request caps at 100, so --count 250 used to return only 100 rows."""
    items = [SimpleNamespace(id=f"ID-{index}", type="source") for index in range(250)]
    client = FakeClient(list(items))

    results = await adapter.search_exploits("query", 250, client=cast(Any, client))

    assert [row.id for row in results] == [f"ID-{index}" for index in range(250)]
    # Offsets advance by rows received, not by the requested limit.
    assert client.search.windows == [(0, 100), (100, 100), (200, 50)]


@pytest.mark.asyncio
async def test_search_stops_when_a_page_comes_back_short() -> None:
    items = [SimpleNamespace(id=f"ID-{index}", type="source") for index in range(120)]
    client = FakeClient(list(items))

    results = await adapter.search_exploits("query", 1000, client=cast(Any, client))

    assert len(results) == 120
    assert client.search.windows == [(0, 100), (100, 100)]


@pytest.mark.asyncio
async def test_search_owns_default_client(monkeypatch: pytest.MonkeyPatch) -> None:
    instances: list[OwnedClient] = []

    class OwnedClient(FakeClient):
        def __init__(self, api_key: str | None, **options: object) -> None:
            super().__init__([SimpleNamespace(id="ID", type="source")])
            self.provided_key = api_key
            self.options = options
            instances.append(self)

        async def __aenter__(self) -> OwnedClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(adapter, "AsyncVulners", OwnedClient)
    results = await adapter.search_exploits("query", 1, "secret")
    assert results[0].id == "ID"
    assert instances[0].provided_key == "secret"
    assert instances[0].options == {"max_response_bytes": 32 * 1024**2}


@pytest.mark.asyncio
async def test_download_uses_sdk_archive(tmp_path: Path) -> None:
    destination = tmp_path / "getsploit.zip"
    client = FakeClient()

    written = await adapter.download_database_archive(
        destination,
        connections=4,
        client=cast(Any, client),
    )

    assert written == len(b"archive")
    assert destination.read_bytes() == b"archive"
    assert client.archive.call == (destination, 4)


@pytest.mark.asyncio
async def test_download_owns_sdk_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    instances: list[OwnedClient] = []

    class OwnedClient(FakeClient):
        def __init__(self, api_key: str | None, **options: object) -> None:
            super().__init__()
            self.provided_key = api_key
            self.options = options
            instances.append(self)

        async def __aenter__(self) -> OwnedClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(adapter, "AsyncVulners", OwnedClient)
    destination = tmp_path / "getsploit.zip"
    assert await adapter.download_database_archive(destination, "secret") == len(b"archive")
    assert destination.read_bytes() == b"archive"
    assert instances[0].provided_key == "secret"
    assert instances[0].options == {"max_response_bytes": 1024**3}
    assert instances[0].archive.call == (destination, 8)


@pytest.mark.asyncio
async def test_installed_sdk_exposes_parallel_download_contract() -> None:
    async with AsyncVulners("test") as client:
        parameters = inspect.signature(client.archive.download_getsploit).parameters
    assert parameters["connections"].default == 8


@pytest.mark.asyncio
async def test_sdk_errors_are_translated() -> None:
    class FailingSearch:
        async def exploits(self, *_args: object, **_kwargs: object) -> None:
            raise VulnersError("failed")

    client = FakeClient()
    client.search = cast(Any, FailingSearch())
    with pytest.raises(adapter.VulnersAdapterError, match="failed"):
        await adapter.search_exploits("query", 1, client=cast(Any, client))


@pytest.mark.asyncio
async def test_sdk_download_errors_are_translated() -> None:
    class FailingArchive:
        async def download_getsploit(self, *_args: object, **_kwargs: object) -> int:
            raise VulnersError("failed")

    client = FakeClient()
    cast(Any, client).archive = FailingArchive()
    with pytest.raises(adapter.VulnersAdapterError, match=r"Cannot download.*failed"):
        await adapter.download_database_archive(Path("archive"), client=cast(Any, client))


@pytest.mark.asyncio
async def test_download_filesystem_errors_are_translated(tmp_path: Path) -> None:
    with pytest.raises(adapter.VulnersAdapterError, match="Cannot download"):
        await adapter.download_database_archive(
            tmp_path / "missing" / "archive",
            client=cast(Any, FakeClient()),
        )


class Reports:
    """Records what a download reported, in the order it reported it."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int, int | None, str]] = []

    def __call__(self, phase: str, completed: int, total: int | None, unit: str) -> None:
        self.calls.append((phase, completed, total, unit))

    @property
    def totals(self) -> list[int | None]:
        return [total for _phase, _completed, total, _unit in self.calls]


async def _watch(monkeypatch: pytest.MonkeyPatch, directory: Path, activity: Any) -> Reports:
    """Run the directory watcher against `activity`, then stop it."""
    monkeypatch.setattr(adapter, "_POLL_SECONDS", 0.001)
    reports = Reports()
    follower = asyncio.create_task(adapter._follow_directory(reports, directory))
    try:
        await activity(reports)
    finally:
        follower.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await follower
    return reports


def test_download_usage_counts_only_regular_files(tmp_path: Path) -> None:
    """The watcher looks at a directory, which also holds entries that are not files."""
    (tmp_path / "subdirectory").mkdir()
    (tmp_path / "archive").write_bytes(b"x" * 8192)

    allocated, reserved = adapter._directory_usage(tmp_path)

    assert reserved == 8192
    assert allocated >= 8192


def test_download_usage_of_an_unreadable_directory_is_zero(tmp_path: Path) -> None:
    """Watching must never be able to fail a download it is only observing."""
    assert adapter._directory_usage(tmp_path / "missing") == (0, 0)


@pytest.mark.asyncio
async def test_download_progress_adopts_the_reserved_total(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The SDK reserves the archive length up front, and that is the download total."""
    reserved_bytes = 64 * 1024 * 1024
    partial = tmp_path / "archive.part"
    with partial.open("wb") as handle:
        handle.seek(reserved_bytes - 1)  # reserve the length without writing data
        handle.write(b"\0")
    if getattr(partial.stat(), "st_blocks", None) is None:
        return  # Windows reports no allocation, so no total can be inferred.

    async def wait_for_a_total(reports: Reports) -> None:
        for _ in range(500):
            await asyncio.sleep(0.001)
            if any(total is not None for total in reports.totals):
                return

    reports = await _watch(monkeypatch, tmp_path, wait_for_a_total)

    adopted = [call for call in reports.calls if call[2] is not None]
    assert adopted, "the reserved length was never adopted as the total"
    phase, completed, total, unit = adopted[0]
    assert (phase, total, unit) == ("Downloading archive", reserved_bytes, "bytes")
    assert completed < reserved_bytes  # only the written blocks count as arrived


@pytest.mark.asyncio
async def test_download_progress_stays_indeterminate_while_the_size_grows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The single-stream fallback reserves nothing, so no total may be invented."""
    streamed = tmp_path / "archive.part"

    async def stream(_reports: Reports) -> None:
        for step in range(1, 12):
            streamed.write_bytes(b"x" * (step * 256 * 1024))
            await asyncio.sleep(0.004)

    reports = await _watch(monkeypatch, tmp_path, stream)

    assert reports.calls
    assert all(total is None for total in reports.totals)


@pytest.mark.asyncio
async def test_download_reports_its_phase_around_the_transfer(tmp_path: Path) -> None:
    reports = Reports()
    destination = tmp_path / "getsploit.zip"

    written = await adapter.download_database_archive(
        destination, progress=reports, client=cast(Any, FakeClient())
    )

    assert reports.calls[0] == ("Downloading archive", 0, None, "bytes")
    assert reports.calls[-1] == ("Downloading archive", written, written, "bytes")


def test_web_search_url_encodes_query() -> None:
    assert adapter.web_search_url("wordpress 4.7").endswith(
        "bulletinFamily%3Aexploit+AND+%28wordpress+4.7%29"
    )
