"""Bound native source coordinates without loading or executing target code."""

import re
from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from diff_gremlin.domain.context import SourceFile
from diff_gremlin.inventory import MAX_FILE_BYTES, MAX_TREE_BYTES

CoordinateKind = Literal["javascript", "eslint", "typescript", "jdk", "javac"]
_MAX_SOURCE_BYTES = MAX_TREE_BYTES
_MAX_CACHED_LINES = 2_000_000
_JS_BREAKS = re.compile(r"\r\n|[\r\n\u2028\u2029]")
_JAVA_BREAKS = re.compile(r"\r\n|[\r\n]")


def _decode_source(contents: bytes, kind: CoordinateKind) -> str:
    if kind == "typescript" and contents[:2] in {b"\xff\xfe", b"\xfe\xff"}:
        encoding = "utf-16-le" if contents[:2] == b"\xff\xfe" else "utf-16-be"
        # Match the compiler host: the BOM is omitted and an odd final byte
        # cannot form a UTF-16 code unit.
        return contents[2 : len(contents) & ~1].decode(encoding, errors="replace")
    return contents.decode("utf-8", errors="replace")


def _lines(text: str, kind: CoordinateKind) -> tuple[str, ...]:
    if kind in {"eslint", "typescript"}:
        text = text.removeprefix("\ufeff")
    breaks = _JAVA_BREAKS if kind in {"jdk", "javac"} else _JS_BREAKS
    lines, start = [], 0
    for match in breaks.finditer(text):
        lines.append(text[start : match.end()])
        start = match.end()
    # JDK tree LineMap retains EOF on its last existing line; diagnostics and
    # JavaScript also represent EOF after a final terminator on an empty line.
    if start < len(text) or kind != "jdk" or not lines:
        lines.append(text[start:])
    return tuple(lines)


@dataclass(frozen=True, slots=True)
class _NativeLine:
    maximum: int
    tabs: tuple[int, ...]

    def contains(self, column: int) -> bool:
        if column > self.maximum:
            return False
        index = bisect_right(self.tabs, column - 1) - 1
        return index < 0 or column > ((self.tabs[index] - 1) // 8 + 1) * 8


def _native_line(text: str, kind: CoordinateKind, *, eof: bool) -> _NativeLine:
    if kind not in {"jdk", "javac"}:
        return _NativeLine(len(text.encode("utf-16-le")) // 2 + int(eof), ())
    cursor, tabs = 1, []
    for character in text:
        if character == "\t":
            tabs.append(cursor)
            cursor = ((cursor - 1) // 8 + 1) * 8 + 1
        else:
            cursor += 2 if ord(character) > 0xFFFF else 1
    return _NativeLine(cursor - 1 + int(eof), tuple(tabs))


class SourceCoordinates:
    """Validate located source under captured-size and cumulative resource bounds."""

    def __init__(self, files: Sequence[SourceFile] = ()) -> None:
        self._remaining = _MAX_SOURCE_BYTES
        self._line_remaining = _MAX_CACHED_LINES
        self._expected = {str(file.path.resolve()): file.size_bytes for file in files}
        self._sources: dict[str, bytes] = {}
        self._lines: dict[tuple[str, CoordinateKind], tuple[_NativeLine, ...]] = {}

    def _source(self, path: str) -> bytes:
        if path not in self._sources:
            expected = self._expected.get(path)
            limit = min(self._remaining, MAX_FILE_BYTES)
            if expected is not None:
                limit = min(limit, expected)
            try:
                with Path(path).open("rb") as stream:
                    contents = stream.read(limit + 1)
            except OSError as error:
                raise ValueError("located source cannot be read") from error
            if len(contents) > self._remaining:
                raise ValueError("located sources exceed coordinate read budget")
            if len(contents) > MAX_FILE_BYTES:
                raise ValueError(
                    "located source exceeds per-file coordinate read budget"
                )
            if expected is not None and len(contents) != expected:
                raise ValueError("located source differs from inventoried size")
            self._remaining -= len(contents)
            self._sources[path] = contents
        return self._sources[path]

    def validate(self, path: str, line: int, column: int, kind: CoordinateKind) -> None:
        key = path, kind
        if key not in self._lines:
            lines = _lines(_decode_source(self._source(path), kind), kind)
            if len(lines) > self._line_remaining:
                raise ValueError("located sources exceed coordinate line budget")
            self._line_remaining -= len(lines)
            self._lines[key] = tuple(
                _native_line(text, kind, eof=index == len(lines) - 1)
                for index, text in enumerate(lines)
            )
        lines = self._lines[key]
        if line > len(lines):
            raise ValueError("finding line outside located source")
        if not lines[line - 1].contains(column):
            raise ValueError("finding column outside native source coordinates")
