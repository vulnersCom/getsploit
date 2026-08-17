# Contributing

Thanks for improving Getsploit. Keep changes small, typed, and easy to verify.

## Setup

Install [uv](https://docs.astral.sh/uv/) and sync the locked environment:

```console
$ uv sync --all-groups
```

The suite never calls the network, so `make check` needs no API key. To exercise
online search locally, copy the template and fill in your own key:

```console
$ cp .env.example .env
$ uv run --env-file .env getsploit CVE-2024-3094
```

`.env` is ignored by git; `.env.example` is the committed template and must stay empty
of real values. Never put a working key in a test, fixture, or documentation example.

## Before opening a pull request

```console
$ make format
$ make lint
$ make coverage
$ make release
```

The coverage gate requires 100% statement and branch coverage for project code. New
tests should assert observable behavior and use a real temporary SQLite database when a
database boundary changes. The normal suite must not call the network.

## Project rules

- Use English in source code, comments, documentation, metadata, and CLI messages.
- Prefer the standard library, then existing dependencies. Add a runtime dependency only
  when it removes more complexity than it introduces.
- Keep async I/O at network boundaries. Move short blocking standard-library calls to a
  worker thread rather than wrapping them in an async database library.
- Preserve stable JSON fields and documented CLI aliases unless the changelog calls out
  a breaking release.
- Do not commit local databases, credentials, editor or AI-assistant state, coverage
  files, generated logs, or temporary development artifacts.
- Never use a production API key in tests or fixtures.
- Keep intentional credential placeholders on the `detect-secrets` inline allowlist;
  never allowlist a real key or an unexplained scanner finding.

Module ownership and database invariants are described in
[ARCHITECTURE.md](ARCHITECTURE.md). Update that file when a boundary changes.

## Commit and pull request scope

One pull request should carry one coherent change. Include:

- the user-visible outcome;
- tests for the changed behavior;
- documentation when CLI or database behavior changes;
- commands used to verify the result.

Security reports do not belong in public issues. Follow [SECURITY.md](SECURITY.md).

A maintainer releases by pushing a `v<version>` tag; everything after that is automated
in [.github/workflows/release.yml](.github/workflows/release.yml), which refuses a tag
that disagrees with `pyproject.toml` or with a `CHANGELOG.md` section still marked
`Unreleased`.
