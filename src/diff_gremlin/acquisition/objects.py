"""Materialize exact Git tree objects without checkout filters or hooks."""

from pathlib import Path

from diff_gremlin.acquisition.blob_stream import blob_batches as _blob_batches
from diff_gremlin.acquisition.git import Git
from diff_gremlin.acquisition.materialize import write_entry
from diff_gremlin.acquisition.object_store import MAX_HISTORY_BYTES, copy_object_store
from diff_gremlin.acquisition.paths import safe_link, safe_path
from diff_gremlin.acquisition.tree import TreeEntry, tree_entries


def extract_tree(git: Git, repo: Path, commit: str, destination: Path) -> tuple[TreeEntry, ...]:
    destination.mkdir()
    entries = tree_entries(git, repo, commit)
    for entry, content in _blob_batches(git, repo, entries):
        if entry.mode == "120000":
            safe_link(entry.path, content.decode("utf-8", "surrogateescape"))
        write_entry(destination, entry.path, entry.mode, content)
    return entries


__all__ = [
    "MAX_HISTORY_BYTES",
    "TreeEntry",
    "copy_object_store",
    "safe_link",
    "safe_path",
    "tree_entries",
]
