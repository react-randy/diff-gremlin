"""Stream bounded stage completion events without changing receipt stdout."""

import sys
from collections.abc import Callable

from diff_gremlin.domain.stages import StageResult
from diff_gremlin.reporting.escaping import plain


def stage_progress(
    *, quiet: bool = False, side: str = ""
) -> Callable[[StageResult], None] | None:
    if quiet:
        return None

    def completed(stage: StageResult) -> None:
        identity = plain(stage.id)[:160]
        prefix = f"{side} " if side else ""
        print(
            f"diff-gremlin: {prefix}{identity}: {stage.status} "
            f"({stage.duration_seconds:.3f}s)",
            file=sys.stderr,
            flush=True,
        )

    return completed
