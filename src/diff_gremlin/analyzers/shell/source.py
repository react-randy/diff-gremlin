"""Read one inventoried snapshot file with bounded race and path checks."""

import os
import stat

from diff_gremlin.domain.context import ScanContext, SourceFile

MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_FILES = 4096
MAX_TOTAL_SOURCE_BYTES = 32 * 1024 * 1024


def read_source(ctx: ScanContext, file: SourceFile) -> str:
    """Reject oversized, replaced, linked, or out-of-snapshot input."""
    if file.size_bytes > MAX_SOURCE_BYTES:
        raise ValueError("Shell source byte limit exceeded")
    if not file.path.resolve().is_relative_to(ctx.root.resolve()):
        raise ValueError("Shell source outside snapshot")
    descriptor = os.open(file.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != file.size_bytes:
            raise ValueError("Shell source changed or is not regular")
        data = stream.read(MAX_SOURCE_BYTES + 1)
        after = os.fstat(stream.fileno())
    if len(data) != file.size_bytes or before.st_mtime_ns != after.st_mtime_ns:
        raise ValueError("Shell source changed while reading")
    return data.decode("utf-8")
