"""Construct evidence for capabilities that could not be observed."""

from diff_gremlin.domain.process import RunResult
from diff_gremlin.domain.stages import Category, StageResult, StageStatus


def unavailable(
    stage_id: str,
    label: str,
    category: Category,
    tool: str,
    reason: str,
    *,
    status: StageStatus = "missing",
    eligible_files: int = 0,
    required: bool = True,
) -> StageResult:
    """Keep unavailable measurements empty rather than inventing clean zeros."""
    return StageResult(
        id=stage_id,
        label=label,
        category=category,
        status=status,
        tool=tool,
        reason=reason,
        eligible_files=eligible_files,
        required=required,
    )


def execution_status(
    result: RunResult, allowed_codes: tuple[int, ...] = (0,)
) -> StageStatus | None:
    """Classify process failure before an adapter validates tool-specific output."""
    if result.status == "ok" and result.returncode in allowed_codes:
        return None
    if result.status == "missing":
        return "missing"
    if result.status == "timeout":
        return "timeout"
    return "failed"
