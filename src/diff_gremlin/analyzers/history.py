"""Expose informational bounded Python complexity observations over Git history."""

from functools import partial
from pathlib import Path

from diff_gremlin.analyzers.history_objects import HistoryLimitError, is_object_id
from diff_gremlin.analyzers.history_reader import HistoryReader
from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult, StageStatus

_ID = "history.git"


def _history_result(
    ctx: ScanContext, rows: list[dict], shallow: bool, anchor: str, limit: int
) -> StageResult:
    limited = shallow or len(rows) == 1
    reason = (
        "Shallow history exposes only the available commit window"
        if shallow
        else ("One commit provides no trend comparison" if len(rows) == 1 else "")
    )
    return StageResult(
        _ID,
        "Python complexity history",
        "history",
        "limited" if limited else "ok",
        "git",
        version=tool_version(ctx, "git"),
        required=False,
        scope="history",
        metrics={
            "rows": rows,
            "commit_count": len(rows),
            "shallow": shallow,
            "limit": limit,
            "revision": anchor,
            "measure": "python-ast-decision-complexity-v1",
            "order": "oldest-first",
            "traversal": "first-parent",
        },
        reason=reason,
        analyzed_files=rows[-1]["files"],
        eligible_files=rows[-1]["files"],
    )


def _request_error(
    ctx: ScanContext, limit: int, revision: str | None
) -> tuple[str, StageStatus] | None:
    if type(limit) is not int or not 1 <= limit <= 50:
        return "History limit must be between 1 and 50", "failed"
    if revision is not None and not is_object_id(revision):
        return "History revision must be a full immutable commit ID", "failed"
    if not any(file.language == "python" for file in ctx.production_files):
        return "History measure supports production Python only", "unsupported"
    return None


def analyze_history(
    ctx: ScanContext,
    history_repo: Path | None = None,
    *,
    limit: int = 10,
    revision: str | None = None,
) -> StageResult:
    failure = partial(
        unavailable, _ID, "Python complexity history", "history", "git", required=False
    )
    request_error = _request_error(ctx, limit, revision)
    if request_error is not None:
        reason, status = request_error
        return failure(reason=reason, status=status)
    reader = HistoryReader(ctx, history_repo if history_repo is not None else ctx.root)
    try:
        if not reader.is_repository():
            return failure(
                reason="History repository root differs from the selected source",
                status="unsupported",
            )
        shallow = reader.is_shallow()
        anchor = reader.revision(revision)
        if not anchor:
            return failure(
                reason="Git repository has no committed history", status="unsupported"
            )
        rows = reader.rows(anchor, limit)
    except FileNotFoundError:
        return failure(reason="Git is not installed", status="missing")
    except TimeoutError:
        return failure(
            reason="Bounded Git history analysis timed out", status="timeout"
        )
    except HistoryLimitError as error:
        return failure(reason=str(error), status="limited")
    except (ValueError, UnicodeError, SyntaxError, RecursionError, MemoryError):
        return failure(
            reason="Git history or Python object analysis failed validation",
            status="failed",
        )
    if not rows:
        return failure(
            reason="No commits available for history analysis", status="unsupported"
        )
    return _history_result(ctx, rows, shallow, anchor, limit)
