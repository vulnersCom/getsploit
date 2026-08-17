# Changelog

All notable changes are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## 3.0.1 — 2026-08-17

The installed package is identical to 3.0.0. This release exists to correct the project
page, which is rendered from the README as it stood at the previous tag.

### Changed

- The version and Python badges are static badges whose URL carries their own value.
  They were live queries whose answers are cached for six hours, so immediately after a
  release — exactly when the page is read — they still advertised the previous version.
  Counters that are genuinely live, such as downloads and stars, stay live.
- The release workflow refuses to publish when those badge values disagree with the
  project version or with the Python classifiers, since a static value can drift where a
  query cannot.

## 3.0.0 — 2026-08-17

### Added

- Asynchronous online search through the official Vulners Python SDK 4.1.
- Adaptive Rich terminal output with table, compact, JSON, and JSONL modes.
- Versioned SQLite FTS5 index with integrity checks and atomic replacement.
- Local database status reporting.
- Progress reporting for `--update`, replacing a single spinner that gave no sense of
  how far a multi-gigabyte update had come. Download shows bytes and throughput,
  unpacking and document conversion show a bar with totals and time remaining in their
  own units, and the two steps with no measurable size stay indeterminate rather than
  displaying a percentage they cannot know.
- Hidden, atomic storage for the optional legacy API-key file.
- Python 3.11–3.14 support and a reproducible `uv` lockfile.
- Parallel tests with a 100% statement and branch coverage gate.
- Secret detection and distribution validation in the release gate.
- Token-free PyPI publishing through GitHub OIDC trusted publishing, triggered by
  pushing a version tag, with signed build provenance and PEP 740 attestations on every
  published artifact.
- CodeQL analysis, OpenSSF Scorecard reporting, dependency review on pull requests, and
  Dependabot updates for both actions and Python dependencies.

### Changed

- Migrated the package to a typed `src` layout and a small, boundary-oriented design.
- Local FTS4 archives are converted to an external-content FTS5 index during update.
- Rebuilt local indexes use FTS5 query syntax; FTS4 `NEAR/n` expressions require the
  equivalent FTS5 `NEAR(...)` form.
- Database archives download atomically through eight parallel range connections and
  remain on disk throughout installation instead of being buffered in memory.
- Mirrored files use exclusive, no-follow creation and never overwrite existing paths.
- Project license changed from GPL-3.0-or-later to MIT.
- JSON serialization now uses the Python standard library.
- `--status` reports the database size in the same units as the progress bars. The two
  used different conventions, so one database read as "1.5 GiB" in one place and
  "1.7 GB" in the other.

### Fixed

- Local search accepts ordinary search words again. `wordpress 4.7`, `CVE-2024-3094`,
  and `ms17-010` were rejected as malformed FTS5 expressions; deliberate FTS5
  expressions still report their own parse errors.
- `--count` above 100 returns the requested number of results. The search endpoint caps
  a single response at 100 documents, so larger counts silently returned only the first
  100; results are now paged, advancing by rows received rather than by the requested
  limit, which would have skipped documents.
- Result tables no longer discard the tail of long identifiers, titles and URLs. Those
  columns wrap instead of being ellipsized, and `--status` shows the full database path.
- Search URLs and mirror paths are no longer folded mid-token, so they stay copyable
  when the terminal is narrower than the value.
- A blank or whitespace-only query reports the usual usage error instead of surfacing a
  `ValueError` traceback from the SDK.
- An empty, zero or non-numeric `COLUMNS` no longer suppresses all output. Rich reports
  a zero-width console for those values, which rendered nothing and still exited 0.
- A missing API key names `VULNERS_API_KEY` and `--set-key` instead of the SDK's
  `api_key=` argument, and is reported before any request is attempted.
- A named pipe left at the API-key path no longer blocks the process forever; the
  regular-file check is now reachable because the open cannot wait for a writer.
- An API-key file that is not valid UTF-8, as written by PowerShell's `>`, reports a
  credential error instead of an unhandled `UnicodeDecodeError`.
- `--mirror` tolerates unbounded third-party identifiers and queries: names are capped
  below the filesystem limit, where a long identifier previously aborted the whole run
  after writing part of it.
- `--mirror` no longer creates an empty directory when a search returns no results.

### Removed

- The unsafe `--api-key VALUE` option; use `VULNERS_API_KEY` or `--set-key` instead.
- Direct HTTP access to Vulners endpoints.
- Runtime dependencies on `httpx`, `orjson`, and `texttable`.

## 2.0.2 — 2025-10-10

- Added Python 3.10 support and explicit API-key resolution.
- Preserved raw query syntax for online and FTS4 searches.
