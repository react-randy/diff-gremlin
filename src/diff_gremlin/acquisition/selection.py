"""Literal immutable-tree selection, independent of Git pathspec syntax."""

from dataclasses import dataclass

from diff_gremlin.acquisition.paths import safe_path
from diff_gremlin.inventory import MAX_ENTRIES, MAX_FILES


def normalize_paths(paths: tuple[str, ...]) -> tuple[str, ...]:
    """Accept bounded repository-relative file/subtree names, never patterns."""
    if len(paths) > 256:
        raise ValueError("Path selection exceeds the limit of 256 literal paths")
    normalized = []
    for path in paths:
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 4096
            or any(ord(char) < 32 or ord(char) == 127 for char in path)
            or any(char in path for char in "\\:*?[]")
            or path.startswith(("/", "-"))
        ):
            raise ValueError(
                "Path selection requires literal repository-relative paths"
            )
        value = path.rstrip("/")
        if any(part in {"", ".", "..", ".git"} for part in value.split("/")):
            raise ValueError("Path selection contains an unsafe or unnormalized path")
        safe_path(value)
        normalized.append(value)
    return tuple(sorted(set(normalized)))


@dataclass(frozen=True, slots=True)
class PathSelection:
    """Intersect explicit literal prefixes with optional exact changed paths."""

    paths: tuple[str, ...] = ()
    changed: frozenset[str] | None = None

    def includes(self, path: str) -> bool:
        return (
            not self.paths
            or any(
                path == prefix or path.startswith(prefix + "/") for prefix in self.paths
            )
        ) and (self.changed is None or path in self.changed)

    def receipt(self, total: int, selected: int) -> dict:
        mode = "paths" if self.changed is None else "changed-paths"
        if self.paths and self.changed is not None:
            mode = "paths-and-changed-paths"
        return {
            "partial": True,
            "mode": mode,
            "paths": list(self.paths),
            "changed_paths": self.changed is not None,
            "counts": {
                "total": total,
                "selected": selected,
                "omitted": total - selected,
            },
            "limits": {
                "max_selected_files": MAX_FILES,
                "max_metadata_entries": MAX_ENTRIES,
            },
        }
