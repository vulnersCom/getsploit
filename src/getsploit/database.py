from __future__ import annotations

import contextlib
import os
import re
import shutil
import sqlite3
import tempfile
import zipfile
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import _limits
from .models import (
    BYTES,
    DOCUMENTS,
    DatabaseStatus,
    Exploit,
    ProgressCallback,
    discard_progress,
)
from .paths import database_path

APPLICATION_ID = 0x4753504C  # GSPL
SCHEMA_VERSION = 1
_DATABASE_NAME = "getsploit.db"
_SQLITE_HEADER = b"SQLite format 3\x00"
_MAX_DATABASE_BYTES = 4 * 1024**3
_WINDOWS = os.name == "nt"
_FTS_OPERATORS = frozenset({"AND", "OR", "NOT", "NEAR"})
# Characters that only appear in a deliberate FTS expression. `.` and `-` are absent:
# they occur in ordinary terms such as `4.7` and `CVE-2024-3094`.
_FTS_SYNTAX_CHARACTERS = frozenset('":()*^')
# One report per 1000 documents: ~280 updates over the real archive, enough to animate a
# bar without making the conversion loop pay for a callback on every row.
_REPORT_EVERY_ROWS = 1000
# Progress phases are display labels. Only this one is reported from two places, where
# either the archive or the already-current database is copied into position.
_COPY_PHASE = "Copying database"

_EXPLOITS_SCHEMA = """
CREATE TABLE exploits (
    id TEXT NOT NULL,
    title TEXT NOT NULL,
    published TEXT NOT NULL,
    description TEXT NOT NULL,
    source_data TEXT NOT NULL,
    vhref TEXT NOT NULL,
    collection TEXT NOT NULL
);
"""

_FTS_SCHEMA = """
CREATE VIRTUAL TABLE exploits_fts USING fts5(
    id,
    title,
    published,
    description,
    source_data,
    content='exploits',
    content_rowid='rowid',
    tokenize='unicode61 remove_diacritics 2'
);
"""

_METADATA_SCHEMA = """
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
"""

# One definition per object, used both to create a database and to validate one. The
# order is the creation order.
_SCHEMAS = {
    "exploits": _EXPLOITS_SCHEMA,
    "exploits_fts": _FTS_SCHEMA,
    "metadata": _METADATA_SCHEMA,
}
_SCHEMA = "\n".join(_SCHEMAS.values())


class DatabaseError(Exception):
    """Base error for the local exploit index."""


class DatabaseNotFoundError(DatabaseError):
    """Raised when local search is requested before the first update."""


class InvalidSearchQueryError(DatabaseError):
    """Raised when SQLite FTS5 rejects a search expression."""


def _plain_terms(query: str) -> list[str] | None:
    """Split a query into ordinary search words, or None when it uses FTS syntax.

    Everyday search words are also FTS metacharacters: `wordpress 4.7` is a syntax
    error and `CVE-2024-3094` parses `2024` as a column name. Recognising a query as
    plain words lets it be matched literally, while a deliberate FTS expression keeps
    reporting its own parse error instead of being silently reinterpreted.
    """
    terms = query.split()
    if not terms:
        return None
    for term in terms:
        if term.upper() in _FTS_OPERATORS or _FTS_SYNTAX_CHARACTERS & set(term):
            return None
    return terms


def _quoted_query(terms: list[str]) -> str:
    # _plain_terms guarantees no term contains a quote, so no escaping is needed.
    return " ".join(f'"{term}"' for term in terms)


def _fts_rows(
    connection: sqlite3.Connection, statement: str, query: str, limit: int
) -> list[Any]:
    """Match `query`, retrying plain search words as quoted literals."""
    try:
        return connection.execute(statement, (query, limit)).fetchall()
    except sqlite3.OperationalError as error:
        terms = _plain_terms(query)
        if terms is None:
            raise InvalidSearchQueryError(f"Invalid FTS query: {error}") from error
        try:
            return connection.execute(statement, (_quoted_query(terms), limit)).fetchall()
        except sqlite3.OperationalError:
            # Report the original failure; it describes what the user actually typed.
            raise InvalidSearchQueryError(f"Invalid FTS query: {error}") from error


class ExploitDatabase:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or database_path()

    def search(self, query: str, limit: int) -> list[Exploit]:
        if not self.path.is_file():
            raise DatabaseNotFoundError("Local database not found. Run 'getsploit --update'.")

        try:
            with contextlib.closing(self._connect_readonly(self.path)) as connection:
                connection.row_factory = sqlite3.Row
                if self._database_format(connection) == "current":
                    return self._search_current(connection, query, limit)
                return self._search_legacy(connection, query, limit)
        except InvalidSearchQueryError:
            raise
        except sqlite3.Error as error:
            raise DatabaseError(f"Cannot read local database: {error}") from error

    def status(self) -> DatabaseStatus:
        if not self.path.is_file():
            raise DatabaseNotFoundError("Local database not found. Run 'getsploit --update'.")

        try:
            return self._status_for(self.path, self.path)
        except (OSError, sqlite3.Error) as error:
            raise DatabaseError(f"Cannot inspect local database: {error}") from error

    def install_archive(
        self, archive: Path, progress: ProgressCallback | None = None
    ) -> DatabaseStatus:
        report = progress or discard_progress
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary_paths: list[Path] = []
        try:
            raw_path = self._temporary_path(".download")
            temporary_paths.append(raw_path)
            built_path = self._temporary_path(".build")
            temporary_paths.append(built_path)
            self._extract_database(archive, raw_path, report)
            if self._is_current_path(raw_path):
                report(_COPY_PHASE, 0, None, "")
                shutil.copyfile(raw_path, built_path)
            else:
                self._build_index(raw_path, built_path, report)
            report("Verifying integrity", 0, None, "")
            self._validate(built_path)
            status = self._status_for(built_path, self.path)
            self._sync_file(built_path)
            built_path.replace(self.path)
            self._sync_directory(self.path.parent)
            return status
        except DatabaseError:
            raise
        except (OSError, sqlite3.Error, zipfile.BadZipFile) as error:
            raise DatabaseError(f"Cannot install local database: {error}") from error
        finally:
            for temporary_path in temporary_paths:
                with contextlib.suppress(FileNotFoundError):
                    temporary_path.unlink()

    @staticmethod
    def _is_current(connection: sqlite3.Connection) -> bool:
        application_id, user_version = ExploitDatabase._versions(connection)
        return application_id == APPLICATION_ID and user_version == SCHEMA_VERSION

    @staticmethod
    def _versions(connection: sqlite3.Connection) -> tuple[int, int]:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        return application_id, user_version

    @classmethod
    def _database_format(cls, connection: sqlite3.Connection) -> str:
        application_id, user_version = cls._versions(connection)
        if application_id == APPLICATION_ID:
            if user_version == SCHEMA_VERSION:
                return "current"
            raise DatabaseError(f"Unsupported Getsploit database schema: {user_version}.")
        cls._assert_legacy_schema(connection)
        return "legacy"

    @classmethod
    def _is_current_path(cls, path: Path) -> bool:
        try:
            with contextlib.closing(sqlite3.connect(path)) as connection:
                application_id, user_version = cls._versions(connection)
                if application_id == APPLICATION_ID and user_version != SCHEMA_VERSION:
                    raise DatabaseError(f"Unsupported Getsploit database schema: {user_version}.")
                return application_id == APPLICATION_ID
        except sqlite3.Error:
            return False

    @staticmethod
    def _search_current(connection: sqlite3.Connection, query: str, limit: int) -> list[Exploit]:
        compatible_query = re.sub(r"\bsourceData\s*:", "source_data:", query, flags=re.IGNORECASE)
        rows = _fts_rows(
            connection,
            """
            SELECT e.id, e.title, e.vhref, e.published, e.description,
                   e.source_data, e.collection
            FROM exploits_fts AS f
            JOIN exploits AS e ON e.rowid = f.rowid
            WHERE exploits_fts MATCH ?
            ORDER BY f.rank
            LIMIT ?
            """,
            compatible_query,
            limit,
        )
        return [Exploit(*row) for row in rows]

    @staticmethod
    def _search_legacy(connection: sqlite3.Connection, query: str, limit: int) -> list[Exploit]:
        rows = _fts_rows(
            connection,
            """
            SELECT id, title, vhref, published, description, sourceData
            FROM exploits
            WHERE exploits MATCH ?
            ORDER BY published DESC
            LIMIT ?
            """,
            query,
            limit,
        )
        return [Exploit(*row) for row in rows]

    def _temporary_path(self, suffix: str) -> Path:
        with tempfile.NamedTemporaryFile(
            prefix=f".{_DATABASE_NAME}.", suffix=suffix, dir=self.path.parent, delete=False
        ) as temporary:
            return Path(temporary.name)

    @staticmethod
    def _connect_readonly(path: Path) -> sqlite3.Connection:
        uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
        return sqlite3.connect(uri, uri=True)

    @staticmethod
    def _extract_database(archive: Path, destination: Path, report: ProgressCallback) -> None:
        size = archive.stat().st_size
        with archive.open("rb") as source:
            header = source.read(len(_SQLITE_HEADER))

        if header == _SQLITE_HEADER:
            if size > _MAX_DATABASE_BYTES:
                raise DatabaseError("Database exceeds the 4 GiB safety limit.")
            report(_COPY_PHASE, 0, None, "")
            shutil.copyfile(archive, destination)
            return

        if size > _limits.MAX_ARCHIVE_BYTES:
            raise DatabaseError("Database archive exceeds the 1 GiB safety limit.")

        with zipfile.ZipFile(archive) as compressed:
            candidates = [
                member
                for member in compressed.infolist()
                if not member.is_dir() and Path(member.filename).name == _DATABASE_NAME
            ]
            if len(candidates) != 1:
                raise DatabaseError(
                    "Database archive must contain exactly one getsploit.db file."
                )
            member = candidates[0]
            if member.file_size > _MAX_DATABASE_BYTES:
                raise DatabaseError("Uncompressed database exceeds the 4 GiB safety limit.")
            try:
                with compressed.open(member) as source, destination.open("wb") as output:
                    copied = 0
                    report("Unpacking archive", copied, member.file_size, BYTES)
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
                        copied += len(chunk)
                        report("Unpacking archive", copied, member.file_size, BYTES)
            except RuntimeError as error:
                raise DatabaseError(f"Cannot read database archive: {error}") from error

    @classmethod
    def _build_index(cls, source_path: Path, target_path: Path, report: ProgressCallback) -> None:
        with (
            contextlib.closing(sqlite3.connect(source_path)) as source,
            contextlib.closing(sqlite3.connect(target_path)) as target,
        ):
            cls._assert_legacy_schema(source)
            target.executescript(_SCHEMA)
            expected = int(source.execute("SELECT count(*) FROM exploits").fetchone()[0])
            rows = source.execute(
                "SELECT id, title, published, description, sourceData, vhref FROM exploits"
            )
            target.executemany(
                """
                INSERT INTO exploits (
                    id, title, published, description, source_data, vhref, collection
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                cls._normalized_rows(rows, expected, report),
            )
            # FTS5 rebuild is one opaque statement, so it can only be announced.
            report("Building FTS5 index", 0, None, "")
            target.execute("INSERT INTO exploits_fts(exploits_fts) VALUES('rebuild')")
            count = target.execute("SELECT count(*) FROM exploits").fetchone()[0]
            target.executemany(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                (
                    ("generated_at", datetime.now(UTC).isoformat()),
                    ("document_count", str(count)),
                ),
            )
            target.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            target.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            target.commit()

    @classmethod
    def _normalized_rows(
        cls, rows: Iterable[tuple[object, ...]], expected: int, report: ProgressCallback
    ) -> Iterator[tuple[str, ...]]:
        """Normalize rows for insertion, reporting every `_REPORT_EVERY_ROWS`.

        Reporting from the generator keeps `executemany` streaming: the rows are never
        collected into a list just to be counted.
        """
        report("Converting documents", 0, expected, DOCUMENTS)
        for index, row in enumerate(rows, start=1):
            yield cls._normalize_row(row)
            if index % _REPORT_EVERY_ROWS == 0:
                report("Converting documents", index, expected, DOCUMENTS)
        report("Converting documents", expected, expected, DOCUMENTS)

    @staticmethod
    def _assert_legacy_schema(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'exploits'"
        ).fetchone()
        if row is None or "fts4" not in row[0].lower():
            raise DatabaseError("Unsupported database archive format.")

    @staticmethod
    def _normalize_row(row: tuple[object, ...]) -> tuple[str, ...]:
        values = tuple("" if value is None else str(value) for value in row)
        exploit_id, title, published, description, source_data, vhref = values
        collection = vhref.rstrip("/").split("/")[-2] if "/" in vhref.rstrip("/") else ""
        return exploit_id, title, published, description, source_data, vhref, collection

    @classmethod
    def _status_for(cls, path: Path, reported_path: Path) -> DatabaseStatus:
        with contextlib.closing(cls._connect_readonly(path)) as connection:
            if cls._database_format(connection) == "current":
                metadata = cls._metadata(connection)
                return DatabaseStatus(
                    path=reported_path,
                    size=path.stat().st_size,
                    documents=int(metadata["document_count"]),
                    schema_version=SCHEMA_VERSION,
                    index="FTS5",
                    generated_at=metadata["generated_at"],
                )
            count = connection.execute("SELECT count(*) FROM exploits").fetchone()[0]
            return DatabaseStatus(
                path=reported_path,
                size=path.stat().st_size,
                documents=int(count),
                schema_version=0,
                index="FTS4 (legacy)",
            )

    @staticmethod
    def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
        metadata = dict(connection.execute("SELECT key, value FROM metadata"))
        missing = {"document_count", "generated_at"} - metadata.keys()
        if missing:
            names = ", ".join(sorted(missing))
            raise DatabaseError(f"Database metadata is missing: {names}.")
        try:
            int(metadata["document_count"])
            datetime.fromisoformat(metadata["generated_at"])
        except (TypeError, ValueError, OverflowError) as error:
            raise DatabaseError("Database metadata is invalid.") from error
        return metadata

    @classmethod
    def _validate(cls, path: Path) -> None:
        with contextlib.closing(sqlite3.connect(path)) as connection:
            if not cls._is_current(connection):
                raise DatabaseError("Database schema version is not supported.")
            quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
            if quick_check != "ok":
                raise DatabaseError(f"SQLite integrity check failed: {quick_check}")
            for name, expected_schema in _SCHEMAS.items():
                definition = connection.execute(
                    "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?",
                    (name,),
                ).fetchone()
                expected = expected_schema.strip().removesuffix(";")
                actual = str(definition[0]).strip() if definition else ""
                if actual != expected:
                    raise DatabaseError(f"Database object {name} has an invalid definition.")
            connection.execute(
                "INSERT INTO exploits_fts(exploits_fts, rank) VALUES('integrity-check', 1)"
            )
            metadata = cls._metadata(connection)
            expected_count = int(metadata["document_count"])
            actual = connection.execute("SELECT count(*) FROM exploits").fetchone()[0]
            if actual != expected_count:
                message = (
                    f"Database document count mismatch: expected {expected_count}, "
                    f"found {actual}."
                )
                raise DatabaseError(message)
            cls._search_current(connection, "__getsploit_validation_probe__", 1)

    @staticmethod
    def _sync_file(path: Path) -> None:
        with path.open("rb+") as file:
            os.fsync(file.fileno())

    @staticmethod
    def _sync_directory(path: Path) -> None:
        if _WINDOWS:
            return
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
