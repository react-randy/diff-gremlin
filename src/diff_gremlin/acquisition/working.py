"""Copy a caller's working tree through descriptor-based, non-following reads."""

import hashlib
import os
import stat
import time
from pathlib import Path

from diff_gremlin.acquisition.git import Git
from diff_gremlin.acquisition.objects import TreeEntry, safe_link, safe_path
from diff_gremlin.inventory import (
    EXCLUDED_DIRECTORIES,
    MAX_ENTRIES,
    MAX_FILE_BYTES,
    MAX_FILES,
    MAX_TREE_BYTES,
)


def in_scope(path: str) -> bool:
    return not any(part in EXCLUDED_DIRECTORIES for part in Path(path).parts[:-1])


def copy_working_tree(
    source: Path, destination: Path, *, deadline: float
) -> dict[str, tuple[str, bytes]]:
    destination.mkdir()
    copied = {}
    total = entries = 0
    try:
        for directory, dirs, files, directory_fd in os.fwalk(
            source, follow_symlinks=False
        ):
            if time.monotonic() >= deadline:
                raise RuntimeError("Working tree copy exceeded acquisition deadline")
            relative = Path(directory).relative_to(source)
            if len(relative.parts) > 64:
                raise RuntimeError(
                    "Working tree exceeds acquisition directory-depth limits"
                )
            entries += len(dirs) + len(files)
            if entries > MAX_ENTRIES:
                raise RuntimeError("Working tree exceeds acquisition entry limits")
            dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRECTORIES]
            links = [
                name
                for name in dirs
                if stat.S_ISLNK(
                    os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode
                )
            ]
            dirs[:] = [name for name in dirs if name not in links]
            for name in [*files, *links]:
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Working tree copy exceeded acquisition deadline"
                    )
                if name == ".git":
                    continue
                path = (relative / name).as_posix()
                safe_path(path)
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    value = os.readlink(name, dir_fd=directory_fd)
                    safe_link(path, value)
                    mode, content = "120000", value.encode("utf-8", "surrogateescape")
                elif stat.S_ISREG(info.st_mode):
                    if info.st_size > MAX_FILE_BYTES:
                        raise RuntimeError(
                            "Working source file exceeds acquisition byte limits"
                        )
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                    with os.fdopen(fd, "rb") as stream:
                        content = stream.read(MAX_FILE_BYTES + 1)
                    if len(content) > MAX_FILE_BYTES:
                        raise RuntimeError(
                            "Working source file grew beyond acquisition byte limits"
                        )
                    mode = "100755" if info.st_mode & stat.S_IXUSR else "100644"
                else:
                    raise RuntimeError(
                        "Working tree contains an unreadable or nonregular source file"
                    )
                total += len(content)
                if len(copied) >= MAX_FILES or total > MAX_TREE_BYTES:
                    raise RuntimeError(
                        "Working tree exceeds acquisition file/count/byte limits"
                    )
                output = destination / path
                output.parent.mkdir(parents=True, exist_ok=True)
                if mode == "120000":
                    output.symlink_to(content.decode("utf-8", "surrogateescape"))
                else:
                    output.write_bytes(content)
                    output.chmod(0o755 if mode == "100755" else 0o644)
                copied[path] = mode, content
    except OSError as exc:
        raise RuntimeError(
            "Working source snapshot could not read a path safely"
        ) from exc
    return copied


def _blob_hash(content: bytes, length: int) -> str:
    hasher = hashlib.sha256() if length == 64 else hashlib.sha1()
    hasher.update(f"blob {len(content)}\0".encode())
    hasher.update(content)
    return hasher.hexdigest()


def working_tree_dirty(
    git: Git, source: Path, tree: tuple[TreeEntry, ...], copied: dict
) -> bool:
    expected = {
        entry.path: (entry.mode, entry.oid) for entry in tree if in_scope(entry.path)
    }
    actual = {
        path: (mode, _blob_hash(content, len(tree[0].oid) if tree else 40))
        for path, (mode, content) in copied.items()
    }
    if actual != expected:
        return True
    index = {}
    for row in git.run(["ls-files", "--stage", "-z"], cwd=source, data=True).split(
        "\0"
    ):
        if not row:
            continue
        metadata, path = row.split("\t", 1)
        mode, oid, stage = metadata.split()
        if stage != "0":
            return True
        if in_scope(path):
            index[path] = mode, oid
    return index != expected
