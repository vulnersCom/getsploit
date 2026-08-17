from __future__ import annotations

import sqlite3
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import cast

import pytest

from getsploit import _limits
from getsploit import database as database_module
from getsploit.database import (
    APPLICATION_ID,
    SCHEMA_VERSION,
    DatabaseError,
    DatabaseNotFoundError,
    ExploitDatabase,
    InvalidSearchQueryError,
)


def test_missing_database_has_actionable_errors(tmp_path: Path) -> None:
    database = ExploitDatabase(tmp_path / "missing.db")
    with pytest.raises(DatabaseNotFoundError, match="--update"):
        database.search("query", 10)
    with pytest.raises(DatabaseNotFoundError, match="--update"):
        database.status()


def test_legacy_database_remains_searchable(legacy_database: Path) -> None:
    database = ExploitDatabase(legacy_database)
    results = database.search("WordPress", 10)
    assert [result.id for result in results] == ["EDB-ID:42"]
    assert database.status().index == "FTS4 (legacy)"


def test_legacy_database_reports_invalid_query(legacy_database: Path) -> None:
    with pytest.raises(InvalidSearchQueryError, match="Invalid FTS query"):
        ExploitDatabase(legacy_database).search('"', 10)


def test_archive_is_migrated_to_versioned_fts5(tmp_path: Path, legacy_archive: Path) -> None:
    database = ExploitDatabase(tmp_path / "home" / "getsploit.db")
    status = database.install_archive(legacy_archive)

    assert status.index == "FTS5"
    assert status.schema_version == SCHEMA_VERSION
    assert status.documents == 2
    assert status.generated_at
    assert database.search("WordPress", 10)[0].collection == "exploitdb"
    assert database.search("sourceData:print", 10)[0].source_data == "print('source')"
    assert database.search("missing", 10) == []
    with pytest.raises(InvalidSearchQueryError, match="Invalid FTS query"):
        database.search('"', 10)


def test_plain_search_words_are_matched_literally(tmp_path: Path, legacy_archive: Path) -> None:
    """Ordinary words must not be read as FTS syntax.

    Matched raw, `2026-01` fails with `no such column: 01`, `CVE-2024-3094` with
    `no such column: 2024`, and `4.7` with a syntax error near `.` -- the last of
    which broke the documented `getsploit --local wordpress 4.7`.
    """
    database = ExploitDatabase(tmp_path / "getsploit.db")
    database.install_archive(legacy_archive)

    assert [row.id for row in database.search("exploit 2026-01", 10)] == ["EDB-ID:42"]
    assert database.search("wordpress 4.7", 10) == []
    assert database.search("CVE-2024-3094", 10) == []


def test_deliberate_fts_syntax_still_reports_its_own_error(
    tmp_path: Path, legacy_archive: Path
) -> None:
    database = ExploitDatabase(tmp_path / "getsploit.db")
    database.install_archive(legacy_archive)

    with pytest.raises(InvalidSearchQueryError, match="Invalid FTS query"):
        database.search('title:"unbalanced', 10)
    with pytest.raises(InvalidSearchQueryError, match="Invalid FTS query"):
        database.search("   ", 10)


def test_unquotable_failure_reports_the_original_error() -> None:
    class FailingConnection:
        def execute(self, *_args: object) -> object:
            raise sqlite3.OperationalError("original failure")

    connection = cast(sqlite3.Connection, FailingConnection())
    with pytest.raises(InvalidSearchQueryError, match="original failure"):
        database_module._fts_rows(connection, "SELECT 1", "plain words", 10)


def test_install_reports_each_phase_with_row_counts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, legacy_archive: Path
) -> None:
    monkeypatch.setattr(database_module, "_REPORT_EVERY_ROWS", 1)
    reports: list[tuple[str, int, int | None, str]] = []

    def record(phase: str, completed: int, total: int | None, unit: str) -> None:
        reports.append((phase, completed, total, unit))

    ExploitDatabase(tmp_path / "getsploit.db").install_archive(legacy_archive, record)

    phases = [phase for phase, _, _, _ in reports]
    assert "Unpacking archive" in phases
    assert "Building FTS5 index" in phases
    assert "Verifying integrity" in phases
    # Unpacking knows the member size, so it reports a real total, measured in bytes.
    unpacking = [
        (done, total, unit)
        for phase, done, total, unit in reports
        if phase == "Unpacking archive"
    ]
    assert unpacking[0][0] == 0
    assert unpacking[-1][0] == unpacking[-1][1]
    assert {unit for _, _, unit in unpacking} == {"bytes"}
    # Conversion counts documents up to the total, including the throttled steps.
    converting = [(done, total) for phase, done, total, unit in reports if unit == "documents"]
    assert converting[0] == (0, 2)
    assert (1, 2) in converting
    assert converting[-1] == (2, 2)
    # Steps with no measurable size must not carry a total to render a percentage from.
    assert [(phase, total) for phase, _, total, unit in reports if not unit] == [
        ("Building FTS5 index", None),
        ("Verifying integrity", None),
    ]


def test_install_without_a_reporter_is_the_default(tmp_path: Path, legacy_archive: Path) -> None:
    assert (
        ExploitDatabase(tmp_path / "getsploit.db").install_archive(legacy_archive).documents == 2
    )


def test_current_raw_database_can_be_installed(tmp_path: Path, legacy_archive: Path) -> None:
    first = ExploitDatabase(tmp_path / "first.db")
    first.install_archive(legacy_archive)
    second = ExploitDatabase(tmp_path / "second.db")

    status = second.install_archive(first.path)

    assert status.documents == 2
    assert second.search("Linux", 10)[0].id == "PACKETSTORM:7"


def test_archive_without_database_is_rejected(tmp_path: Path) -> None:
    archive_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("other.txt", "data")
    with pytest.raises(DatabaseError, match="exactly one"):
        ExploitDatabase(tmp_path / "db").install_archive(archive_path)


def test_archive_with_multiple_databases_is_rejected(tmp_path: Path) -> None:
    archive_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("a/getsploit.db", "one")
        archive.writestr("b/getsploit.db", "two")
    with pytest.raises(DatabaseError, match="exactly one"):
        ExploitDatabase(tmp_path / "db").install_archive(archive_path)


def test_large_database_member_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(database_module, "_MAX_DATABASE_BYTES", 0)
    archive_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("getsploit.db", "x")
    with pytest.raises(DatabaseError, match="4 GiB"):
        ExploitDatabase(tmp_path / "db").install_archive(archive_path)


def test_large_archive_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(_limits, "MAX_ARCHIVE_BYTES", 0)
    archive_path = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("getsploit.db", "x")
    with pytest.raises(DatabaseError, match="1 GiB"):
        ExploitDatabase(tmp_path / "db").install_archive(archive_path)


def test_large_raw_database_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(database_module, "_MAX_DATABASE_BYTES", 0)
    archive_path = tmp_path / "archive.db"
    archive_path.write_bytes(b"SQLite format 3\x00data")
    with pytest.raises(DatabaseError, match="4 GiB"):
        ExploitDatabase(tmp_path / "db").install_archive(archive_path)


def test_invalid_zip_is_wrapped(tmp_path: Path) -> None:
    archive_path = tmp_path / "archive.zip"
    archive_path.write_bytes(b"not an archive")
    with pytest.raises(DatabaseError, match="Cannot install local database"):
        ExploitDatabase(tmp_path / "db").install_archive(archive_path)


def test_unknown_sqlite_schema_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "unknown.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE other(value TEXT)")
    with pytest.raises(DatabaseError, match="Unsupported database archive format"):
        ExploitDatabase(tmp_path / "target.db").install_archive(source)


def test_unsupported_known_schema_is_not_treated_as_legacy(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as connection:
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute("PRAGMA user_version = 99")
    database = ExploitDatabase(path)
    with pytest.raises(DatabaseError, match="Unsupported Getsploit database schema: 99"):
        database.search("query", 1)
    with pytest.raises(DatabaseError, match="Unsupported Getsploit database schema: 99"):
        database.status()
    with pytest.raises(DatabaseError, match="Unsupported Getsploit database schema: 99"):
        ExploitDatabase(tmp_path / "target.db").install_archive(path)


def test_status_wraps_invalid_schema(tmp_path: Path) -> None:
    path = tmp_path / "invalid.db"
    with sqlite3.connect(path) as connection:
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    with pytest.raises(DatabaseError, match="Cannot inspect local database"):
        ExploitDatabase(path).status()


def test_search_wraps_corrupt_database(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"SQLite format 3\x00broken")
    with pytest.raises(DatabaseError, match="Cannot read local database"):
        ExploitDatabase(path).search("query", 1)


def test_install_wraps_filesystem_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fail(_archive: Path, _destination: Path, _report: object) -> None:
        raise OSError("disk full")

    archive_path = tmp_path / "archive"
    archive_path.touch()
    database = ExploitDatabase(tmp_path / "db")
    monkeypatch.setattr(database, "_extract_database", fail)
    with pytest.raises(DatabaseError, match="disk full"):
        database.install_archive(archive_path)


def test_install_cleans_first_candidate_when_second_creation_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, legacy_archive: Path
) -> None:
    database = ExploitDatabase(tmp_path / "db")
    original = database._temporary_path
    calls = 0

    def create(suffix: str) -> Path:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("cannot create candidate")
        return original(suffix)

    monkeypatch.setattr(database, "_temporary_path", create)
    with pytest.raises(DatabaseError, match="cannot create candidate"):
        database.install_archive(legacy_archive)
    assert list(tmp_path.glob(".getsploit.db.*")) == []


def test_failed_update_preserves_installed_database(tmp_path: Path, legacy_archive: Path) -> None:
    database = ExploitDatabase(tmp_path / "db")
    database.install_archive(legacy_archive)
    original = database.path.read_bytes()
    invalid_archive = tmp_path / "invalid.zip"
    with zipfile.ZipFile(invalid_archive, "w") as archive:
        archive.writestr("other.txt", "data")

    with pytest.raises(DatabaseError, match="exactly one"):
        database.install_archive(invalid_archive)

    assert database.path.read_bytes() == original
    assert database.search("WordPress", 1)[0].id == "EDB-ID:42"


def test_integrity_check_detects_external_content_drift(
    tmp_path: Path, legacy_archive: Path
) -> None:
    source = ExploitDatabase(tmp_path / "source.db")
    source.install_archive(legacy_archive)
    with sqlite3.connect(source.path) as connection:
        connection.execute("DELETE FROM exploits WHERE rowid = 1")
    with pytest.raises(DatabaseError, match="Cannot install local database"):
        ExploitDatabase(tmp_path / "target.db").install_archive(source.path)


def test_document_count_mismatch_is_rejected(tmp_path: Path, legacy_archive: Path) -> None:
    source = ExploitDatabase(tmp_path / "source.db")
    source.install_archive(legacy_archive)
    with sqlite3.connect(source.path) as connection:
        connection.execute("UPDATE metadata SET value = '99' WHERE key = 'document_count'")
    with pytest.raises(DatabaseError, match="document count mismatch"):
        ExploitDatabase(tmp_path / "target.db").install_archive(source.path)


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        ("DELETE FROM metadata WHERE key = 'generated_at'", "metadata is missing"),
        (
            "UPDATE metadata SET value = 'invalid' WHERE key = 'generated_at'",
            "metadata is invalid",
        ),
        (
            "UPDATE metadata SET value = x'32303236' WHERE key = 'generated_at'",
            "metadata is invalid",
        ),
    ],
)
def test_invalid_metadata_is_rejected(
    tmp_path: Path, legacy_archive: Path, statement: str, message: str
) -> None:
    source = ExploitDatabase(tmp_path / "source.db")
    source.install_archive(legacy_archive)
    with sqlite3.connect(source.path) as connection:
        connection.execute(statement)
    with pytest.raises(DatabaseError, match=message):
        ExploitDatabase(tmp_path / "target.db").install_archive(source.path)


def test_marker_matching_database_requires_exact_schema(
    tmp_path: Path, legacy_archive: Path
) -> None:
    source = ExploitDatabase(tmp_path / "source.db")
    source.install_archive(legacy_archive)
    with sqlite3.connect(source.path) as connection:
        connection.execute("ALTER TABLE exploits DROP COLUMN collection")
    with pytest.raises(DatabaseError, match="exploits has an invalid definition"):
        ExploitDatabase(tmp_path / "target.db").install_archive(source.path)


def test_marker_matching_database_requires_exact_column_contract(
    tmp_path: Path, legacy_archive: Path
) -> None:
    source = ExploitDatabase(tmp_path / "source.db")
    source.install_archive(legacy_archive)
    with sqlite3.connect(source.path) as connection:
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            "UPDATE sqlite_schema SET sql = replace(sql, 'id TEXT', 'id INTEGER') "
            "WHERE type = 'table' AND name = 'exploits'"
        )
    with pytest.raises(DatabaseError, match="exploits has an invalid definition"):
        ExploitDatabase(tmp_path / "target.db").install_archive(source.path)


def test_marker_matching_database_requires_external_content_fts5(
    tmp_path: Path, legacy_archive: Path
) -> None:
    source = ExploitDatabase(tmp_path / "source.db")
    source.install_archive(legacy_archive)
    with sqlite3.connect(source.path) as connection:
        connection.execute("DROP TABLE exploits_fts")
        connection.execute(
            """
            CREATE VIRTUAL TABLE exploits_fts USING fts5(
                id, title, published, description, source_data,
                tokenize='unicode61 remove_diacritics 2'
            )
            """
        )
    with pytest.raises(DatabaseError, match="exploits_fts has an invalid definition"):
        ExploitDatabase(tmp_path / "target.db").install_archive(source.path)


def test_fts5_configuration_preserves_quoted_whitespace(
    tmp_path: Path, legacy_archive: Path
) -> None:
    source = ExploitDatabase(tmp_path / "source.db")
    source.install_archive(legacy_archive)
    with sqlite3.connect(source.path) as connection:
        connection.execute("DROP TABLE exploits_fts")
        connection.execute(
            """
            CREATE VIRTUAL TABLE exploits_fts USING fts5(
                id,
                title,
                published,
                description,
                source_data,
                content='ex ploits',
                content_rowid='rowid',
                tokenize='unicode61 remove_diacritics 2'
            )
            """
        )
    with pytest.raises(DatabaseError, match="exploits_fts has an invalid definition"):
        ExploitDatabase(tmp_path / "target.db").install_archive(source.path)


def test_fts5_configuration_preserves_quoted_unicode(
    tmp_path: Path, legacy_archive: Path
) -> None:
    source = ExploitDatabase(tmp_path / "source.db")
    source.install_archive(legacy_archive)
    with sqlite3.connect(source.path) as connection:
        connection.execute("DROP TABLE exploits_fts")
        connection.execute(
            """
            CREATE VIRTUAL TABLE exploits_fts USING fts5(
                id,
                title,
                published,
                description,
                source_data,
                content='exploit\u017f',
                content_rowid='rowid',
                tokenize='unicode61 remove_diacritics 2'
            )
            """
        )
    with pytest.raises(DatabaseError, match="exploits_fts has an invalid definition"):
        ExploitDatabase(tmp_path / "target.db").install_archive(source.path)


def test_ranked_search_does_not_build_temporary_sort(
    tmp_path: Path, legacy_archive: Path
) -> None:
    database = ExploitDatabase(tmp_path / "db")
    database.install_archive(legacy_archive)
    with sqlite3.connect(database.path) as connection:
        plan = connection.execute(
            """
            EXPLAIN QUERY PLAN
            SELECT e.id
            FROM exploits_fts AS f
            JOIN exploits AS e ON e.rowid = f.rowid
            WHERE exploits_fts MATCH ?
            ORDER BY f.rank
            LIMIT ?
            """,
            ("WordPress", 10),
        ).fetchall()
    assert all("TEMP B-TREE" not in detail for *_prefix, detail in plan)


def test_simultaneous_updates_leave_a_valid_database(
    tmp_path: Path, legacy_archive: Path
) -> None:
    database = ExploitDatabase(tmp_path / "db")
    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(database.install_archive, (legacy_archive, legacy_archive)))
    assert [status.documents for status in statuses] == [2, 2]
    assert database.status().documents == 2


def test_schema_version_validation(tmp_path: Path) -> None:
    path = tmp_path / "version.db"
    with sqlite3.connect(path) as connection:
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
    with pytest.raises(DatabaseError, match="schema version"):
        ExploitDatabase._validate(path)


def test_quick_check_failure_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    class Cursor:
        def __init__(self, value: object) -> None:
            self.value = value

        def fetchone(self) -> tuple[object]:
            return (self.value,)

    class Connection:
        def execute(self, statement: str) -> Cursor:
            if statement == "PRAGMA application_id":
                return Cursor(APPLICATION_ID)
            if statement == "PRAGMA user_version":
                return Cursor(SCHEMA_VERSION)
            return Cursor("damaged")

        def close(self) -> None:
            return None

    monkeypatch.setattr(sqlite3, "connect", lambda _path: Connection())
    with pytest.raises(DatabaseError, match="integrity check failed: damaged"):
        ExploitDatabase._validate(tmp_path / "db")


def test_current_path_probe_handles_invalid_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "broken.db"
    path.write_bytes(b"broken")
    assert ExploitDatabase._is_current_path(path) is False


def test_encrypted_archive_error_is_wrapped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, legacy_archive: Path
) -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("password required")

    monkeypatch.setattr(zipfile.ZipFile, "open", fail)
    with pytest.raises(DatabaseError, match="Cannot read database archive"):
        ExploitDatabase(tmp_path / "db").install_archive(legacy_archive)


def test_row_normalization_handles_nulls_and_missing_collection() -> None:
    assert ExploitDatabase._normalize_row(("ID", None, None, None, None, "url")) == (
        "ID",
        "",
        "",
        "",
        "",
        "url",
        "",
    )


def test_windows_directory_sync_is_a_noop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(database_module, "_WINDOWS", True)
    ExploitDatabase._sync_directory(tmp_path)
