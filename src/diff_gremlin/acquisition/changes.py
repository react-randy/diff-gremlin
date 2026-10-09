"""Bounded changed-path and line metadata from the exact two captured objects."""

import re
from dataclasses import dataclass
from pathlib import Path

from diff_gremlin.acquisition.git import Git
from diff_gremlin.acquisition.paths import safe_path
from diff_gremlin.acquisition.selection import PathSelection
from diff_gremlin.acquisition.tree import MAX_METADATA_BYTES
from diff_gremlin.inventory import MAX_ENTRIES

LineMap = dict[str, tuple[tuple[int, int], ...]]
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
DIFF_OPTIONS = ["--no-ext-diff", "--no-textconv", "--no-renames", "--no-color"]


@dataclass(frozen=True, slots=True)
class ChangedPath:
    path: str
    status: str


def comparison_history(git: Git, base: Path, head: Path, destination: Path) -> Path:
    """Join two owned object views without changing either snapshot's pinned HEAD."""
    before = git.run(["rev-parse", "--show-object-format"], cwd=base).strip()
    after = git.run(["rev-parse", "--show-object-format"], cwd=head).strip()
    if before != after or before not in {"sha1", "sha256"}:
        raise RuntimeError("Comparison objects have incompatible Git object formats")
    git.run(["init", "--bare", f"--object-format={before}", str(destination)])
    (destination / "objects" / "info" / "alternates").write_text(
        "".join(str(repo.resolve() / "objects") + "\n" for repo in (base, head))
    )
    return destination


def _raw_entries(text: str) -> tuple[ChangedPath, ...]:
    if not text:
        return ()
    parts = text.split("\0")
    if parts.pop() != "" or len(parts) % 2:
        raise RuntimeError("Git changed-path metadata is incomplete")
    paths = []
    for index in range(0, len(parts), 2):
        metadata, path = parts[index : index + 2]
        fields = metadata.split()
        if (
            len(fields) != 5
            or not fields[0].startswith(":")
            or fields[-1] not in {"A", "D", "M", "T"}
        ):
            raise RuntimeError("Git changed-path metadata has an unsupported entry")
        safe_path(path)
        paths.append(ChangedPath(path, fields[-1]))
        if len(paths) > MAX_ENTRIES:
            raise RuntimeError(f"Changed-path metadata exceeds limit {MAX_ENTRIES}")
    if len({entry.path for entry in paths}) != len(paths):
        raise RuntimeError("Git changed-path metadata contains duplicate paths")
    return tuple(paths)


def changed_paths(git: Git, repo: Path, base: str, head: str) -> tuple[str, ...]:
    text = git.run(
        ["diff", *DIFF_OPTIONS, "--raw", "-z", base, head, "--"],
        cwd=repo,
        data=True,
        limit=MAX_METADATA_BYTES,
    )
    return tuple(entry.path for entry in _raw_entries(text))


def _interval(start: str, count: str | None) -> tuple[int, int] | None:
    length = int(count) if count is not None else 1
    return (int(start), int(start) + length - 1) if length else None


def _patch_lines(
    text: str, entries: tuple[ChangedPath, ...]
) -> tuple[LineMap, LineMap]:
    before: dict[str, list[tuple[int, int]]] = {
        row.path: [] for row in entries if row.status != "A"
    }
    after: dict[str, list[tuple[int, int]]] = {
        row.path: [] for row in entries if row.status != "D"
    }
    current = -1
    for line in text.split("\n"):
        if line.startswith("diff --git "):
            current += 1
            if current >= len(entries):
                raise RuntimeError("Git patch has unexpected file metadata")
        elif match := HUNK.match(line):
            if current < 0:
                raise RuntimeError("Git patch has hunk metadata before its file")
            old_start, old_count, new_start, new_count = match.groups()
            if interval := _interval(old_start, old_count):
                before[entries[current].path].append(interval)
            if interval := _interval(new_start, new_count):
                after[entries[current].path].append(interval)
    if current + 1 != len(entries):
        raise RuntimeError("Git patch is missing file metadata")
    return (
        {path: tuple(intervals) for path, intervals in before.items()},
        {path: tuple(intervals) for path, intervals in after.items()},
    )


def changed_lines(
    git: Git,
    repo: Path,
    base: str,
    head: str,
    selection: PathSelection | None,
) -> tuple[LineMap | None, LineMap | None]:
    """An oversized/unavailable patch yields unknown maps, never guessed locations."""
    prefixes = [f":(literal){path}" for path in selection.paths] if selection else []
    try:
        text = git.run(
            [
                "diff",
                *DIFF_OPTIONS,
                "--raw",
                "-z",
                "--patch",
                "--unified=0",
                base,
                head,
                "--",
                *prefixes,
            ],
            cwd=repo,
            data=True,
            limit=MAX_METADATA_BYTES,
        )
    except RuntimeError:
        return None, None
    if not text:
        return {}, {}
    raw, separator, patch = text.partition("\0\0")
    if not separator:
        raise RuntimeError("Git patch is missing its bounded raw metadata")
    entries = _raw_entries(raw + "\0")
    return _patch_lines(patch, entries)
