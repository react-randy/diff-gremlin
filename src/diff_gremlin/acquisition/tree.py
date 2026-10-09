"""Read bounded Git source tree metadata."""

from dataclasses import dataclass
from pathlib import Path

from diff_gremlin.acquisition.git import Git
from diff_gremlin.acquisition.paths import safe_path
from diff_gremlin.acquisition.selection import PathSelection
from diff_gremlin.inventory import MAX_ENTRIES, MAX_FILES

MAX_METADATA_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class TreeEntry:
    path: str
    mode: str
    oid: str
    size: int


def tree_entries(
    git: Git,
    repo: Path,
    commit: str,
    *,
    selection: PathSelection | None = None,
    selection_counts: dict | None = None,
) -> tuple[TreeEntry, ...]:
    """Bound metadata globally and content by selection; retain all links for safety."""
    text = git.run(
        ["ls-tree", "-r", "-z", "-l", commit],
        cwd=repo,
        data=True,
        limit=MAX_METADATA_BYTES,
    )
    entries = []
    total, selected = 0, 0
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
        total += 1
        if total > MAX_ENTRIES:
            raise RuntimeError(
                f"Source tree metadata exceeds limit {MAX_ENTRIES}; found at least {total} entries"
            )
        included = selection is None or selection.includes(path)
        selected += included
        if included or mode == "120000":
            entries.append(TreeEntry(path, mode, oid, size))
    if selected > MAX_FILES:
        qualifier = "selected " if selection is not None else ""
        raise RuntimeError(
            f"Source tree exceeds bounded file/count limit {MAX_FILES}; found {selected} {qualifier}files"
        )
    if selection_counts is not None:
        selection_counts.update(total=total, selected=selected)
    return tuple(entries)
