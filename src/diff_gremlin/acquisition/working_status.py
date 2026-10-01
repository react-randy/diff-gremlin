"""Compare captured working source with the repository tree and index."""

import hashlib
from pathlib import Path

from diff_gremlin.acquisition.git import Git
from diff_gremlin.acquisition.tree import TreeEntry
from diff_gremlin.inventory import EXCLUDED_DIRECTORIES


def in_scope(path: str) -> bool:
    return not any(part in EXCLUDED_DIRECTORIES for part in Path(path).parts[:-1])


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
    return _index_entries(git, source) != expected


def _index_entries(git: Git, source: Path) -> dict[str, tuple[str, str]] | None:
    index = {}
    for row in git.run(["ls-files", "--stage", "-z"], cwd=source, data=True).split(
        "\0"
    ):
        if not row:
            continue
        metadata, path = row.split("\t", 1)
        mode, oid, stage = metadata.split()
        if stage != "0":
            return None
        if in_scope(path):
            index[path] = mode, oid
    return index
