"""Convert explicit user gates into stable CLI exit codes."""

from dataclasses import dataclass

from diff_gremlin.domain.findings import SEVERITY_ORDER
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.assessment import Assessment


@dataclass(frozen=True, slots=True)
class Gates:
    fail_under: float | None = None
    fail_on: str | None = None
    require_complete: bool = False


def threshold_failed(assessment: Assessment, threshold: float | None) -> bool:
    return threshold is not None and assessment.score is not None and assessment.score < threshold


def severity_failed(stages: list[StageResult], severity: str | None) -> bool:
    if severity is None:
        return False
    floor = SEVERITY_ORDER[severity]
    return any(SEVERITY_ORDER[f.severity] >= floor for stage in stages for f in stage.findings)


def exit_code(assessment: Assessment, stages: list[StageResult], gates: Gates) -> int:
    """1 known gate failure; 3 incomplete; operational/usage errors use 2."""
    if (
        assessment.blockers
        or threshold_failed(assessment, gates.fail_under)
        or severity_failed(stages, gates.fail_on)
    ):
        return 1
    if not assessment.complete:
        return 3
    return 0
