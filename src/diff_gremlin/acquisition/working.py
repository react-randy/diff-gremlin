"""Traverse a caller working tree within acquisition resource limits."""

import os
import stat
import time
from pathlib import Path

from diff_gremlin.acquisition.materialize import write_entry
from diff_gremlin.acquisition.paths import safe_path
from diff_gremlin.acquisition.scope import working_scope
from diff_gremlin.acquisition.working_capture import capture_entry
from diff_gremlin.acquisition.working_status import in_scope, working_tree_dirty
from diff_gremlin.domain.sources import SourceScopeEntry
from diff_gremlin.inventory import (
    EXCLUDED_DIRECTORIES,
    MAX_ENTRIES,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TREE_BYTES,
)


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise RuntimeError("Working tree copy exceeded acquisition deadline")


def _directory_links(dirs: list[str], directory_fd: int) -> list[str]:
    dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_DIRECTORIES)
    links = [
        name
        for name in dirs
        if stat.S_ISLNK(
            os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode
        )
    ]
    dirs[:] = [name for name in dirs if name not in links]
    return links


def _entry_count(
    relative: Path, dirs: list[str], files: list[str], entries: int
) -> int:
    if len(relative.parts) > 64:
        raise RuntimeError("Working tree exceeds acquisition directory-depth limits")
    entries += len(dirs) + len(files)
    if entries > MAX_ENTRIES:
        raise RuntimeError("Working tree exceeds acquisition entry limits")
    return entries


def copy_working_tree(
    source: Path,
    destination: Path,
    *,
    deadline: float,
    scope_manifest: list[SourceScopeEntry] | None = None,
    oid_length: int = 40,
) -> dict[str, tuple[str, bytes | str]]:
    destination.mkdir()
    copied: dict[str, tuple[str, bytes | str]] = {}
    total = entries = read_total = 0

    def directory_error(error):
        if scope_manifest is None:
            raise error
        path = Path(error.filename or source).relative_to(source).as_posix()
        scope_manifest.append(
            SourceScopeEntry(
                path,
                0,
                "possible-source",
                f"Working source directory unreadable ({type(error).__name__})",
            )
        )

    try:
        for directory, dirs, files, directory_fd in os.fwalk(
            source, follow_symlinks=False, onerror=directory_error
        ):
            _check_deadline(deadline)
            relative = Path(directory).relative_to(source)
            entries = _entry_count(relative, dirs, files, entries)
            links = _directory_links(dirs, directory_fd)
            for name in sorted([*files, *links]):
                _check_deadline(deadline)
                if name == ".git":
                    continue
                path = (relative / name).as_posix()
                safe_path(path)
                try:
                    mode, content, size, oid, read = capture_entry(
                        name,
                        path,
                        directory_fd,
                        limit=MAX_FILE_BYTES,
                        read_budget=max(0, MAX_TREE_BYTES - read_total),
                        deadline=deadline,
                        oid_length=oid_length,
                    )
                    read_total += read
                except OSError as error:
                    if scope_manifest is None:
                        raise
                    scope_manifest.append(
                        SourceScopeEntry(
                            path,
                            0,
                            "possible-source",
                            f"Working source metadata/content unreadable ({type(error).__name__})",
                        )
                    )
                    copied[path] = "100644", ""
                    continue
                omission = working_scope(
                    path,
                    mode,
                    content,
                    size,
                    oid,
                    limit=MAX_FILE_BYTES,
                    exhausted=len(copied) >= MAX_FILES
                    or total + len(content) > MAX_TREE_BYTES,
                )
                if omission is not None:
                    if scope_manifest is None:
                        raise RuntimeError("Working tree exceeds acquisition limits")
                    scope_manifest.append(omission)
                    copied[path] = mode, oid
                    continue
                total += len(content)
                write_entry(destination, path, mode, content)
                copied[path] = mode, content
    except OSError as exc:
        raise RuntimeError(
            "Working source snapshot could not read a path safely"
        ) from exc
    return copied


__all__ = ["in_scope", "working_tree_dirty"]
