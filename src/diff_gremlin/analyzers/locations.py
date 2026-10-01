"""Resolve analyzer locations against the inventoried source allowlist."""

from collections.abc import Sequence
from pathlib import Path

from diff_gremlin.domain.context import SourceFile


class SourceLocations:
    """Canonical source identities owned by one observation batch."""

    __slots__ = ("_allowed", "_root")

    def __init__(self, root: Path, files: Sequence[SourceFile]) -> None:
        self._root = root
        self._allowed = {file.path.resolve(): file.relative_path for file in files}

    def relative(self, value: object) -> str:
        """Resolve each candidate afresh and reject non-inventory locations."""
        if not isinstance(value, str) or not value or "\x00" in value:
            raise ValueError("invalid source location")
        candidate = Path(value)
        candidate = candidate if candidate.is_absolute() else self._root / candidate
        try:
            return self._allowed[candidate.resolve()]
        except (KeyError, OSError, RuntimeError) as exc:
            raise ValueError("source location outside analyzed inventory") from exc


def relative_location(root: Path, value: object, files: Sequence[SourceFile]) -> str:
    """Resolve a single location; batches should share SourceLocations instead."""
    return SourceLocations(root, files).relative(value)
