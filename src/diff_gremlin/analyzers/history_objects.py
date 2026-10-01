"""Validate bounded Python tree entries and Git batch blob framing."""

import re
from pathlib import Path

_OBJECT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_MAX_FILES = 500
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


def python_entries(text: str) -> list[tuple[str, str]]:
    entries = []
    for record in text.split("\x00"):
        if not record:
            continue
        metadata, path = record.split("\t", 1)
        mode, kind, sha = metadata.split(" ")
        if not is_object_id(sha):
            raise ValueError("invalid Git object identity")
        if mode in ("100644", "100755") and kind == "blob" and _production_python(path):
            entries.append((sha, path))
    if len(entries) > _MAX_FILES:
        raise ValueError("history commit exceeds bounded Python file inventory")
    return entries


def blob_contents(text: str, entries: list[tuple[str, str]]) -> list[str]:
    payload = text.encode("utf-8")
    position = 0
    contents = []
    for sha, _ in entries:
        end = payload.index(b"\n", position)
        header = payload[position:end].decode("ascii").split(" ")
        if len(header) != 3 or header[:2] != [sha, "blob"]:
            raise ValueError("Git batch object identity mismatch")
        size = int(header[2])
        if size < 0 or size > 1024 * 1024:
            raise ValueError("history Python blob exceeds size bound")
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
