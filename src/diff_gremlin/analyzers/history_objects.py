"""Validate bounded Python tree entries and Git batch blob framing."""

import re
from dataclasses import dataclass
from pathlib import Path

from diff_gremlin.inventory import MAX_FILE_BYTES, MAX_FILES, MAX_TREE_BYTES

_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_IGNORED_PARTS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "tests",
        "test",
        "testing",
        "migrations",
    }
)


def is_object_id(value: object) -> bool:
    return isinstance(value, str) and _OBJECT_ID.fullmatch(value) is not None


def _production_python(path: str) -> bool:
    file = Path(path)
    return (
        file.suffix == ".py"
        and not _IGNORED_PARTS.intersection(file.parts)
        and not file.name.startswith("test_")
        and not file.name.endswith("_test.py")
    )


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    oid: str
    path: str
    size: int


class HistoryLimitError(ValueError):
    """A named resource boundary exhausted without corrupt Git evidence."""


def _python_entry(record: str) -> HistoryEntry | None:
    """Validate one Git identity and select a bounded production Python blob."""
    metadata, path = record.split("\t", 1)
    mode, kind, sha, size_text = metadata.split()
    if not is_object_id(sha):
        raise ValueError("invalid Git object identity")
    if (
        mode not in ("100644", "100755")
        or kind != "blob"
        or not _production_python(path)
    ):
        return None
    size = int(size_text)
    if size < 0:
        raise ValueError("negative historical source size")
    if size > MAX_FILE_BYTES:
        raise HistoryLimitError("History Python source exceeds the 8 MiB file budget")
    return HistoryEntry(sha, path, size)


def python_entries(text: str) -> list[HistoryEntry]:
    entries = []
    for record in filter(None, text.split("\x00")):
        entry = _python_entry(record)
        if entry is not None:
            entries.append(entry)
    total = sum(entry.size for entry in entries)
    if len(entries) > MAX_FILES or total > MAX_TREE_BYTES:
        raise HistoryLimitError(
            "History commit exceeds the 20,000-file/256 MiB source budget"
        )
    return entries


def blob_contents(text: str, entries: list[HistoryEntry]) -> list[str]:
    payload = text.encode("utf-8")
    position = 0
    contents = []
    for entry in entries:
        end = payload.index(b"\n", position)
        header = payload[position:end].decode("ascii").split(" ")
        if len(header) != 3 or header[:2] != [entry.oid, "blob"]:
            raise ValueError("Git batch object identity mismatch")
        size = int(header[2])
        if size != entry.size:
            raise ValueError("history Python blob differs from captured size")
        position = end + 1
        body = payload[position : position + size]
        position += size
        if payload[position : position + 1] != b"\n":
            raise ValueError("truncated Git batch object")
        position += 1
        contents.append(body.decode("utf-8"))
    if position != len(payload):
        raise ValueError("unexpected Git batch output")
    return contents
