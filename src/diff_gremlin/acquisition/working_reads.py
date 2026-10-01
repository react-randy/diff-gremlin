"""Read working source entries without following filesystem links."""

import os
import stat

from diff_gremlin.acquisition.paths import safe_link
from diff_gremlin.inventory import MAX_FILE_BYTES


def _regular_file(name: str, directory_fd: int, info: os.stat_result) -> bytes:
    if info.st_size > MAX_FILE_BYTES:
        raise RuntimeError("Working source file exceeds acquisition byte limits")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as stream:
        content = stream.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES:
        raise RuntimeError("Working source file grew beyond acquisition byte limits")
    return content


def read_entry(name: str, path: str, directory_fd: int) -> tuple[str, bytes]:
    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode):
        value = os.readlink(name, dir_fd=directory_fd)
        safe_link(path, value)
        return "120000", value.encode("utf-8", "surrogateescape")
    if stat.S_ISREG(info.st_mode):
        content = _regular_file(name, directory_fd, info)
        return ("100755" if info.st_mode & stat.S_IXUSR else "100644"), content
    raise RuntimeError("Working tree contains an unreadable or nonregular source file")
