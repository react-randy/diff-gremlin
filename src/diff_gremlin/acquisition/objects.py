"""Extract exact Git blobs without checkout hooks, attributes, or filters."""

import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from diff_gremlin.acquisition.git import Git
from diff_gremlin.inventory import (
    MAX_ENTRIES,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TREE_BYTES,
)

MAX_HISTORY_BYTES = 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class TreeEntry:
    path: str
    mode: str
    oid: str
    size: int


def safe_path(path: str) -> PurePosixPath:
    value = PurePosixPath(path)
    if (
        value.is_absolute()
        or any(part in {"..", ".git"} for part in value.parts)
        or not value.parts
    ):
        raise RuntimeError("Source tree contains an unsafe path")
    return value


def safe_link(path: str, target: str) -> None:
    if not target or PurePosixPath(target).is_absolute():
        raise RuntimeError("Source symbolic link escapes its snapshot")
    parts = list(PurePosixPath(path).parent.parts)
    for part in PurePosixPath(target).parts:
        if part == "..":
            if not parts:
                raise RuntimeError("Source symbolic link escapes its snapshot")
            parts.pop()
        elif part != ".":
            parts.append(part)


def tree_entries(git: Git, repo: Path, commit: str) -> tuple[TreeEntry, ...]:
    text = git.run(["ls-tree", "-r", "-z", "-l", commit], cwd=repo, data=True)
    entries = []
    total = 0
    for row in text.split("\0"):
        if not row:
            continue
        metadata, path = row.split("\t", 1)
        mode, kind, oid, size = metadata.split()
        safe_path(path)
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise RuntimeError(
                "Source tree contains a submodule or unsupported object; materialize it explicitly first"
            )
        size = int(size)
        total += size
        if len(entries) >= MAX_FILES or size > MAX_FILE_BYTES or total > MAX_TREE_BYTES:
            raise RuntimeError("Source tree exceeds bounded file/count/byte limits")
        entries.append(TreeEntry(path, mode, oid, size))
    return tuple(entries)


def _blob_batches(git: Git, repo: Path, entries: tuple[TreeEntry, ...]):
    """Batch reads to avoid launching one Git process for each source file."""
    pending = list(entries)
    offset = 0
    while offset < len(pending):
        batch = []
        size = 0
        while offset < len(pending) and (not batch or size < 1024 * 1024):
            entry = pending[offset]
            batch.append(entry)
            size += entry.size
            offset += 1
        text = git.run(
            ["cat-file", "--batch"],
            cwd=repo,
            data=True,
            input_text="".join(f"{entry.oid}\n" for entry in batch),
            limit=size + len(batch) * 128 + 1,
        )
        output = text.encode("utf-8", "surrogateescape")
        cursor = 0
        for entry in batch:
            end = output.find(b"\n", cursor)
            if end < 0:
                raise RuntimeError("Git blob batch has an incomplete object header")
            header = output[cursor:end].decode().split()
            if header != [entry.oid, "blob", str(entry.size)]:
                raise RuntimeError(
                    "Git blob batch differs from the captured tree metadata"
                )
            cursor = end + 1
            data = output[cursor : cursor + entry.size]
            cursor += entry.size
            if len(data) != entry.size or output[cursor : cursor + 1] != b"\n":
                raise RuntimeError("Git blob batch has an incomplete object body")
            cursor += 1
            yield entry, data
        if cursor != len(output):
            raise RuntimeError("Git blob batch contains unexpected trailing data")


def extract_tree(
    git: Git, repo: Path, commit: str, destination: Path
) -> tuple[TreeEntry, ...]:
    destination.mkdir()
    entries = tree_entries(git, repo, commit)
    for entry, data in _blob_batches(git, repo, entries):
        path = destination / entry.path
        path.parent.mkdir(parents=True, exist_ok=True)
        if entry.mode == "120000":
            target = data.decode("utf-8", "surrogateescape")
            safe_link(entry.path, target)
            path.symlink_to(target)
        else:
            path.write_bytes(data)
            path.chmod(0o755 if entry.mode == "100755" else 0o644)
    return entries


def copy_object_store(source: Path, destination: Path, *, deadline: float) -> None:
    """Copy inert object bytes, excluding external alternates and every configuration file."""
    count = total = 0
    for directory, dirs, files, directory_fd in os.fwalk(source, follow_symlinks=False):
        if time.monotonic() >= deadline:
            raise RuntimeError("Git object copy exceeded acquisition deadline")
        relative = Path(directory).relative_to(source)
        count += len(dirs)
        if count > MAX_ENTRIES or len(relative.parts) > 64:
            raise RuntimeError("Git object store exceeds entry/directory-depth limits")
        dirs[:] = [d for d in dirs if d != "info"]
        output = destination / relative
        output.mkdir(parents=True, exist_ok=True)
        for name in files:
            count += 1
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise RuntimeError("Git object store contains a nonregular object")
                total += info.st_size
                if count > MAX_ENTRIES or total > MAX_HISTORY_BYTES:
                    raise RuntimeError("Git object history exceeds acquisition limits")
                with (output / name).open("wb") as target:
                    remaining = info.st_size
                    while remaining:
                        if time.monotonic() >= deadline:
                            raise RuntimeError(
                                "Git object copy exceeded acquisition deadline"
                            )
                        chunk = stream.read(min(remaining, 65536))
                        if not chunk:
                            raise RuntimeError("Git object changed during acquisition")
                        target.write(chunk)
                        remaining -= len(chunk)
                    if stream.read(1):
                        raise RuntimeError("Git object grew during acquisition")
