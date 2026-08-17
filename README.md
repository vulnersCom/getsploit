<div align="center">

# Getsploit

**Search and download public exploits from the [Vulners](https://vulners.com) database —
online, or fully offline from a local index.**

[![PyPI](https://img.shields.io/badge/pypi-v3.0.0-0073b7?logo=pypi&logoColor=white)](https://pypi.org/project/getsploit/)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-0073b7?logo=python&logoColor=white)](https://pypi.org/project/getsploit/)
[![Downloads](https://img.shields.io/pepy/dt/getsploit?logo=python&logoColor=white&label=downloads&color=0073b7)](https://pepy.tech/project/getsploit)
[![Stars](https://img.shields.io/github/stars/vulnersCom/getsploit?logo=github&logoColor=white)](https://github.com/vulnersCom/getsploit/stargazers)
[![CI](https://github.com/vulnersCom/getsploit/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/vulnersCom/getsploit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/vulnersCom/getsploit/actions/workflows/codeql.yml/badge.svg?branch=master)](https://github.com/vulnersCom/getsploit/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/vulnersCom/getsploit/badge)](https://scorecard.dev/viewer/?uri=github.com/vulnersCom/getsploit)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/vulnersCom/getsploit/actions/workflows/ci.yml)
[![Typed](https://img.shields.io/badge/typing-PEP%20561-brightgreen)](https://peps.python.org/pep-0561/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Get an API key](https://vulners.com/userinfo) ·
[Vulners search](https://vulners.com/search) ·
[Changelog](CHANGELOG.md) ·
[Architecture](ARCHITECTURE.md) ·
[Security policy](SECURITY.md)

<img src="https://raw.githubusercontent.com/vulnersCom/getsploit/master/docs/demo.gif"
     alt="Getsploit searching online, building a local FTS5 index, then searching and mirroring offline"
     width="900">

</div>

---

## Why Getsploit

- 🔎 **One query, every collection.** Exploit-DB, Metasploit, Packet Storm, Zero Day
  Initiative, GitHub proof-of-concepts and more, as indexed by Vulners.
- 📴 **Works with the network off.** One `--update` builds a local SQLite FTS5 index of
  the whole exploit corpus; every later search is a local query.
- 🧠 **Searches for what you typed.** `wordpress 4.7`, `CVE-2024-3094` and `ms17-010`
  match literally, while a deliberate full-text expression still gets full FTS5 syntax.
- 📊 **Progress you can trust.** Every stage of an update reports real numbers, and the
  two stages whose size cannot be known say so instead of inventing a percentage.
- 🧾 **Pipe-friendly.** JSON, JSON Lines, and stable tab-separated records when the
  output is redirected. No colour or decoration ever reaches a machine format.
- 💾 **Keeps the source.** `--mirror` writes each exploit body to its own file.
- 🔐 **Careful with your data.** The key is never a command-line argument, the key file
  is opened without following symlinks, and downloaded content is never executed.
- 🧪 **Verified.** 100% statement and branch coverage on Python 3.11 through 3.14, on
  Linux, macOS and Windows.

---

## Install

Getsploit needs Python 3.11 or newer.

```console
$ pipx install getsploit
```

```console
$ uv tool install getsploit
```

```console
$ python -m pip install getsploit
```

## API key

Create a key in your [Vulners account](https://vulners.com/userinfo), then expose it
through the environment:

```console
$ export VULNERS_API_KEY="your-key"  # pragma: allowlist secret
```

```powershell
$env:VULNERS_API_KEY = "your-key"  # pragma: allowlist secret
```

`getsploit --set-key` stores a key through a hidden confirmation prompt, in a private
file under the Getsploit home. The environment takes precedence over that file and is
the better choice for automation. There is no `--api-key` option: a key passed on the
command line ends up in the shell history and in the process list.

Online search and `--update` need a key. `--local` and `--status` do not.

## Usage

### Online search

```console
$ getsploit CVE-2024-3094
$ getsploit "wordpress 4.7 remote code execution" --count 25
```

The query reaches Vulners unchanged, so its
[Lucene syntax](https://vulners.com/docs) works as documented:

```console
$ getsploit 'title:wordpress AND description:"code execution"'
```

`--count` above 100 is paged transparently; a single API response never carries more
than 100 documents.

### Offline search

```console
$ getsploit --update                 # download the archive and build the FTS5 index
$ getsploit --status                 # where it is, how big, how many documents
$ getsploit --local wordpress 4.7
```

Ordinary search words are matched literally, so identifiers and version numbers work as
typed: `wordpress 4.7`, `CVE-2024-3094`, `ms17-010`. A query that uses column filters,
boolean operators, quotes, parentheses, `*` or `^` is treated as an
[SQLite FTS5 expression](https://www.sqlite.org/fts5.html) and reports its own error
when malformed:

```console
$ getsploit --local 'title:eternalblue AND NOT description:metasploit'
```

Searchable columns are `id`, `title`, `published`, `description` and `source_data`. The
legacy `sourceData:` spelling is still accepted.

### Saving exploit sources

```console
$ getsploit --mirror wordpress 4.7
$ getsploit --local --mirror eternalblue
```

Files land in a directory derived from the query, one file per exploit, created without
following symlinks and never overwriting anything that already exists.

> [!WARNING]
> Mirrored files are untrusted third-party code. Read them before running them.

### Machine-readable output

```console
$ getsploit --format json CVE-2024-3094
$ getsploit --format jsonl wordpress | jq -r .id
$ getsploit wordpress > results.tsv       # redirected output is tab-separated
```

`--json` remains an alias for `--format json`.

### Terminal control

```console
$ getsploit --color always query | less -R
$ getsploit --color never query
```

Colour defaults to `auto`. A wide terminal gets a table, a narrow one gets stacked
records, and a redirected stream gets tab-separated values — the same data in all three.

Run `getsploit --help` for the full option list.

## The local database

| | |
| --- | --- |
| Location | `~/.getsploit/getsploit.db`, or `$GETSPLOIT_HOME` |
| Format | SQLite with an external-content FTS5 index |
| Tokenizer | `unicode61 remove_diacritics 2` |
| Size | roughly 1.7 GB for the full corpus |
| Update | atomic: the new database replaces the old one in a single operation |

An update downloads the archive over eight parallel range connections, unpacks and
converts it beside the destination, verifies it, and only then commits. Memory use does
not depend on the size of the archive. A search already running against the old database
finishes against it undisturbed.

Databases built by Getsploit 2.x remain searchable; the next `--update` migrates them
from FTS4 to FTS5. FTS4 proximity expressions such as `one NEAR/5 two` must be rewritten
in the FTS5 `NEAR(...)` form.

## Compatibility

| | |
| --- | --- |
| Python | 3.11, 3.12, 3.13, 3.14 |
| Operating systems | Linux, macOS, Windows |
| Vulners SDK | 4.1 and newer 4.x |
| Runtime dependencies | `click`, `rich`, `vulners` |

## Development

```console
$ git clone https://github.com/vulnersCom/getsploit.git
$ cd getsploit
$ uv sync --all-groups
$ make check
```

| Command | Purpose |
| --- | --- |
| `make format` | Format and autofix source files |
| `make lint` | Check formatting, lint, and types |
| `make test` | Run tests in parallel |
| `make coverage` | Enforce 100% statement and branch coverage |
| `make leaks` | Scan tracked files for secrets |
| `make build` | Build the wheel and source distribution |
| `make release` | Run every gate and validate both distributions |
| `make check` | Everything above that gates a merge |

[CONTRIBUTING.md](CONTRIBUTING.md) has the contribution rules and
[ARCHITECTURE.md](ARCHITECTURE.md) the module boundaries and database invariants.

A release is a pushed `v<version>` tag. From there
[the release workflow](.github/workflows/release.yml) re-runs the full gate on the
tagged commit, publishes to PyPI through trusted publishing, and writes the GitHub
release from the changelog. No PyPI token exists to leak.

## Security

Exploit source files are untrusted content: review them before opening or running them.
Getsploit itself never executes what it downloads.

Releases are published from GitHub Actions through PyPI trusted publishing, so no
long-lived API token exists to leak, and every artifact carries a build provenance
attestation. To report a vulnerability in Getsploit, follow [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © Vulners Team and contributors.
