"""Traverse a caller working tree within acquisition resource limits."""

import os
import stat
import time
from pathlib import Path

from diff_gremlin.acquisition.materialize import write_entry
from diff_gremlin.acquisition.paths import safe_path
from diff_gremlin.acquisition.working_reads import read_entry
from diff_gremlin.acquisition.working_status import in_scope as in_scope
from diff_gremlin.acquisition.working_status import working_tree_dirty as working_tree_dirty
from diff_gremlin.inventory import EXCLUDED_DIRECTORIES, MAX_ENTRIES, MAX_FILES, MAX_TREE_BYTES


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RuntimeError("Working tree copy exceeded acquisition deadline")


def _directory_links(dirs: list[str], directory_fd: int) -> list[str]:
    dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRECTORIES]
    links = [
        name
        for name in dirs
        if stat.S_ISLNK(os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode)
    ]
    dirs[:] = [name for name in dirs if name not in links]
    return links


def _entry_count(relative: Path, dirs: list[str], files: list[str], entries: int) -> int:
    if len(relative.parts) > 64:
        raise RuntimeError("Working tree exceeds acquisition directory-depth limits")
    entries += len(dirs) + len(files)
    if entries > MAX_ENTRIES:
        raise RuntimeError("Working tree exceeds acquisition entry limits")
    return entries


def copy_working_tree(
    source: Path, destination: Path, *, deadline: float
) -> dict[str, tuple[str, bytes]]:
    destination.mkdir()
    copied: dict[str, tuple[str, bytes]] = {}
    total = entries = 0
    try:
        for directory, dirs, files, directory_fd in os.fwalk(source, follow_symlinks=False):
            _check_deadline(deadline)
            relative = Path(directory).relative_to(source)
            entries = _entry_count(relative, dirs, files, entries)
            links = _directory_links(dirs, directory_fd)
            for name in [*files, *links]:
                _check_deadline(deadline)
                if name == ".git":
                    continue
                path = (relative / name).as_posix()
                safe_path(path)
                mode, content = read_entry(name, path, directory_fd)
                total += len(content)
                if len(copied) >= MAX_FILES or total > MAX_TREE_BYTES:
                    raise RuntimeError("Working tree exceeds acquisition file/count/byte limits")
                write_entry(destination, path, mode, content)
                copied[path] = mode, content
    except OSError as exc:
        raise RuntimeError("Working source snapshot could not read a path safely") from exc
    return copied
