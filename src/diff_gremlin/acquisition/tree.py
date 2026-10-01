"""Read bounded Git source tree metadata."""

from dataclasses import dataclass
from pathlib import Path

from diff_gremlin.acquisition.git import Git
from diff_gremlin.acquisition.paths import safe_path
from diff_gremlin.inventory import MAX_FILE_BYTES, MAX_FILES, MAX_TREE_BYTES


@dataclass(frozen=True, slots=True)
class TreeEntry:
    path: str
    mode: str
    oid: str
    size: int


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
