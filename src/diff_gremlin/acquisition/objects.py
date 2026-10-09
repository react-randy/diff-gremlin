"""Materialize exact Git tree objects without checkout filters or hooks."""

from pathlib import Path

from diff_gremlin.acquisition.blob_stream import blob_batches as _blob_batches
from diff_gremlin.acquisition.git import Git
from diff_gremlin.acquisition.materialize import write_entry
from diff_gremlin.acquisition.object_store import MAX_HISTORY_BYTES, copy_object_store
from diff_gremlin.acquisition.paths import safe_link, safe_path
from diff_gremlin.acquisition.scope import content_scope
from diff_gremlin.acquisition.selection import PathSelection
from diff_gremlin.acquisition.tree import TreeEntry, tree_entries
from diff_gremlin.domain.sources import SourceScopeEntry
from diff_gremlin.inventory import MAX_FILE_BYTES, MAX_TREE_BYTES
from diff_gremlin.source_paths import in_scope


def _selected_entries(
    entries: tuple[TreeEntry, ...], scope_manifest: list[SourceScopeEntry] | None
) -> tuple[TreeEntry, ...]:
    """Select bounded in-scope content and retain every symlink for validation."""
    selected = []
    read_bytes = 0
    for entry in entries:
        if entry.mode != "120000" and not in_scope(entry.path):
            continue
        if read_bytes + entry.size > MAX_TREE_BYTES:
            if scope_manifest is None or entry.mode == "120000":
                raise RuntimeError("Source tree exceeds bounded byte limits")
            scope_manifest.append(
                SourceScopeEntry(
                    entry.path,
                    entry.size,
                    "possible-source",
                    "Content exceeds aggregate acquisition read budget",
                )
            )
        else:
            selected.append(entry)
            read_bytes += entry.size
    return tuple(selected)


def extract_tree(
    git: Git,
    repo: Path,
    commit: str,
    destination: Path,
    *,
    scope_manifest: list[SourceScopeEntry] | None = None,
    selection: PathSelection | None = None,
    selection_counts: dict | None = None,
) -> tuple[TreeEntry, ...]:
    destination.mkdir()
    entries = tree_entries(
        git, repo, commit, selection=selection, selection_counts=selection_counts
    )
    for entry, content in _blob_batches(
        git, repo, _selected_entries(entries, scope_manifest)
    ):
        if entry.mode == "120000":
            safe_link(entry.path, content.decode("utf-8", "surrogateescape"))
        if not in_scope(entry.path) or (
            selection is not None and not selection.includes(entry.path)
        ):
            continue
        if entry.mode != "120000" and scope_manifest is not None:
            omission = content_scope(entry.path, content, entry.size, MAX_FILE_BYTES)
            if omission is not None:
                scope_manifest.append(omission)
                continue
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
