"""Read and parse bounded regular Python source without executing it."""

import ast
import os
import stat
import time

from diff_gremlin.domain.context import SourceFile

MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_AST_NODES = 500_000


class SourceLimit(ValueError):
    """A safe resource reason produced by this reader, never source text."""


def read_source(file: SourceFile) -> str:
    """Read only the inventoried bytes of one unchanged regular file."""
    if file.size_bytes > MAX_SOURCE_BYTES:
        raise SourceLimit("Python source byte limit exceeded")
    descriptor = os.open(file.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != file.size_bytes:
            raise ValueError("Python source changed or is not regular")
        data = stream.read(MAX_SOURCE_BYTES + 1)
        after = os.fstat(stream.fileno())
    if len(data) != file.size_bytes or before.st_mtime_ns != after.st_mtime_ns:
        raise ValueError("Python source changed while reading")
    return data.decode("utf-8")


def bounded_tree(source: str, deadline: float) -> ast.Module:
    """Parse without execution and bound subsequent AST traversal."""
    if time.monotonic() >= deadline:
        raise TimeoutError("Python parsing time budget exhausted")
    tree = ast.parse(source)
    for count, _ in enumerate(ast.walk(tree), 1):
        if count % 1024 == 0 and time.monotonic() >= deadline:
            raise TimeoutError("Python parsing time budget exhausted")
        if count > MAX_AST_NODES:
            raise SourceLimit("Python AST node limit exceeded")
    return tree


def parse_source(file: SourceFile, deadline: float) -> ast.Module:
    """Prepare one bounded, source-verified AST for call observations."""
    return bounded_tree(read_source(file), deadline)
