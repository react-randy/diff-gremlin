"""Resolve analyzer locations against the inventoried source allowlist."""

from collections.abc import Sequence
from pathlib import Path

from diff_gremlin.domain.context import SourceFile


def relative_location(root: Path, value: object, files: Sequence[SourceFile]) -> str:
    """Reject unknown paths rather than attributing external data to this scan."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("invalid source location")
    candidate = Path(value)
    candidate = candidate if candidate.is_absolute() else root / candidate
    allowed = {file.path.resolve(): file.relative_path for file in files}
    try:
        return allowed[candidate.resolve()]
    except (KeyError, OSError, RuntimeError) as exc:
        raise ValueError("source location outside analyzed inventory") from exc
