"""Locate source bytes with the PHP lexer CR, CRLF and LF line convention."""

import re
from bisect import bisect_right


def line_starts(source: bytes) -> tuple[int, ...]:
    return (0, *(match.end() for match in re.finditer(rb"\r\n|\r|\n", source)))


def token_position(starts: tuple[int, ...], offset: int) -> tuple[int, int]:
    line = bisect_right(starts, offset)
    return line, offset - starts[line - 1] + 1
