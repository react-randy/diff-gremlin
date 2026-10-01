"""Copy inert Git object bytes within history resource limits."""

import os
import stat
import time
from pathlib import Path
from typing import BinaryIO

from diff_gremlin.inventory import MAX_ENTRIES

MAX_HISTORY_BYTES = 1024 * 1024 * 1024


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RuntimeError("Git object copy exceeded acquisition deadline")


def _copy_bytes(stream: BinaryIO, target: BinaryIO, size: int, deadline: float) -> None:
    remaining = size
    while remaining:
        _check_deadline(deadline)
        chunk = stream.read(min(remaining, 65536))
        if not chunk:
            raise RuntimeError("Git object changed during acquisition")
        target.write(chunk)
        remaining -= len(chunk)
    if stream.read(1):
        raise RuntimeError("Git object grew during acquisition")


def _copy_object(
    name: str, directory_fd: int, output: Path, count: int, total: int, deadline: float
) -> int:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("Git object store contains a nonregular object")
        total += info.st_size
        if count > MAX_ENTRIES or total > MAX_HISTORY_BYTES:
            raise RuntimeError("Git object history exceeds acquisition limits")
        with (output / name).open("wb") as target:
            _copy_bytes(stream, target, info.st_size, deadline)
    return total


def copy_object_store(source: Path, destination: Path, *, deadline: float) -> None:
    count = total = 0
    for directory, dirs, files, directory_fd in os.fwalk(source, follow_symlinks=False):
        _check_deadline(deadline)
        relative = Path(directory).relative_to(source)
        count += len(dirs)
        if count > MAX_ENTRIES or len(relative.parts) > 64:
            raise RuntimeError("Git object store exceeds entry/directory-depth limits")
        dirs[:] = [d for d in dirs if d != "info"]
        output = destination / relative
        output.mkdir(parents=True, exist_ok=True)
        for name in files:
            count += 1
            total = _copy_object(name, directory_fd, output, count, total, deadline)
