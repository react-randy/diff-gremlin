"""Capture bounded regular-file text and stable Git identity in one safe read."""

import hashlib
import os
import stat
import time


def capture_regular(name, directory_fd, *, limit, read_budget, deadline, oid_length=40):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError(
                "Working source changed to a nonregular file during acquisition"
            )
        hasher = hashlib.sha256() if oid_length == 64 else hashlib.sha1()
        hasher.update(f"blob {before.st_size}\0".encode())
        captured = bytearray()
        read = 0
        maximum = min(before.st_size, read_budget)
        while read < maximum:
            if time.monotonic() >= deadline:
                raise RuntimeError("Working tree copy exceeded acquisition deadline")
            chunk = stream.read(min(65536, maximum - read))
            if not chunk:
                break
            hasher.update(chunk)
            captured.extend(chunk[: max(0, limit + 1 - len(captured))])
            read += len(chunk)
        after = os.fstat(stream.fileno())
        complete = read == before.st_size and (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) == (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        mode = "100755" if before.st_mode & stat.S_IXUSR else "100644"
        return (
            mode,
            bytes(captured),
            before.st_size,
            hasher.hexdigest() if complete else "",
            read,
        )


def capture_entry(
    name, path, directory_fd, *, limit, read_budget, deadline, oid_length
):
    """Capture a regular file or an inert, containment-validated symbolic link."""
    from diff_gremlin.acquisition.working_reads import read_entry

    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if stat.S_ISREG(info.st_mode):
        return capture_regular(
            name,
            directory_fd,
            limit=limit,
            read_budget=read_budget,
            deadline=deadline,
            oid_length=oid_length,
        )
    mode, content = read_entry(name, path, directory_fd)
    return mode, content, len(content), "", 0
