# Architecture

Getsploit is a small command-line application with three external boundaries: the
Vulners SDK, SQLite, and the terminal/filesystem. Dependencies point from the CLI toward
those boundaries and the immutable `Exploit` model; boundary modules never import the
CLI.

```text
cli ───────> vulners ───────> official Vulners SDK
 │              │
 ├────────> database ───────> sqlite3 / local database
 ├────────> credentials ────> private legacy key file
 ├────────> files ──────────> downloaded exploit files
 └────────> output ─────────> Rich / JSON / plain text

models <────────── all feature modules
paths  <────────── database / credentials
limits <────────── database / Vulners adapter
```

## Module ownership

| Module | Owns |
| --- | --- |
| `models` | Immutable `Exploit` and `DatabaseStatus` cross-boundary values |
| `paths` | Getsploit home, database, and legacy credential locations |
| `_limits` | Security limits shared by independent input boundaries |
| `credentials` | Safe loading and atomic storage of the legacy API-key file |
| `vulners` | SDK lifecycle, API projection, and conversion from SDK bulletins |
| `database` | Database schema, migration, validation, search, status, and replacement |
| `files` | Safe directory and filename derivation for mirrored exploit bodies |
| `output` | Terminal layout and machine-readable serialization |
| `cli` | Option validation, async orchestration, and user-facing error boundaries |

There is no repository interface or service layer. The application has two concrete
search paths, both returning the same value type, and no shared mutable domain state.

## Data flows

### Online search

```text
query -> AsyncVulners.search.exploits -> SDK bulletin -> Exploit -> renderer
```

### Local search

```text
query -> asyncio.to_thread -> SQLite FTS5 -> Exploit -> renderer
```

SQLite work stays synchronous because the standard library is sufficient and local
queries are short. The CLI moves it to a worker thread so the async orchestration loop
remains responsive. Search and status connections use SQLite's read-only immutable mode;
an in-flight POSIX reader can finish against the previous inode while an update commits.

### Database update

```text
AsyncVulners.archive.download_getsploit(path, connections=8)
  -> atomic, parallel archive download in constant memory
  -> bounded ZIP validation and streamed member copy
  -> legacy FTS4 read-only source
  -> new FTS5 database beside the destination
  -> SQLite + FTS integrity checks
  -> fsync
  -> atomic replacement
```

Vulners SDK 4.1 downloads the archive to a temporary path over parallel HTTP range
connections, falls back to a single stream when necessary, and commits that file
atomically. Getsploit passes the path directly to the database boundary, so neither the
network adapter nor the installer holds the archive or the extracted database in memory.
The compressed archive is capped at 1 GiB and its SQLite member at 4 GiB before migration.

## Local database

`database.ExploitDatabase` owns the file and every schema decision.

- `PRAGMA application_id = 0x4753504c` identifies a Getsploit artifact.
- `PRAGMA user_version = 1` identifies the schema.
- `exploits` stores document fields once.
- `exploits_fts` is an external-content FTS5 index over searchable fields.
- `metadata` stores the build timestamp and expected document count.
- `unicode61 remove_diacritics 2` is the initial tokenizer.
- No prefix index or custom BM25 weights are used until a representative benchmark
  proves that the additional size improves real queries.

An installed database must pass all of these checks before replacement:

1. Expected application and schema identifiers.
2. `PRAGMA quick_check`.
3. FTS5 external-content integrity check.
4. Stored and actual document counts match.

Legacy FTS4 databases remain searchable. The next successful update migrates them to
FTS5, so there is no separate migration command or mutable in-place upgrade.

Each update builds a uniquely named candidate and replaces the destination in one
filesystem operation. Concurrent updates therefore commit complete generations only.
Windows may reject replacement while another process still holds the database open; the
old database remains intact and the update reports an error.

## Invariants

- Search results cross module boundaries only as immutable `Exploit` values.
- JSON and JSONL contain data only; terminal decoration never leaks into them.
- Validation and migration failures happen before the atomic database commit point.
- Downloaded archives and extracted SQLite members are processed with bounded memory.
- Archive members are copied to a chosen path, never extracted by their archive path.
- Runtime code has no dependency on the test, build, or formatting toolchain.
- Every statement and branch in project code is covered by the deterministic test suite.
