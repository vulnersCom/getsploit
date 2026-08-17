from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

# Installation progress, reported as (phase, completed, total, unit). A total of None
# means the step has no measurable size, so a renderer shows it as indeterminate rather
# than inventing a percentage. The unit says how to read the numbers.
ProgressCallback = Callable[[str, int, int | None, str], None]

BYTES = "bytes"
DOCUMENTS = "documents"


def discard_progress(_phase: str, _completed: int, _total: int | None, _unit: str) -> None:
    """Default sink, so a reporting path needs no branch per report."""


@dataclass(frozen=True, slots=True)
class Exploit:
    id: str
    title: str
    url: str
    published: str = ""
    description: str = ""
    source_data: str = ""
    collection: str = ""

    @property
    def content(self) -> str:
        return self.source_data or self.description


@dataclass(frozen=True, slots=True)
class DatabaseStatus:
    path: Path
    size: int
    documents: int
    schema_version: int
    index: str
    generated_at: str = ""
