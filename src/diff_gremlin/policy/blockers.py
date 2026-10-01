"""Publish known policy blockers even when other evidence is missing."""

from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.metrics import number


def metric_blockers(stage: StageResult) -> list[str]:
    if stage.category == "complexity" and (number(stage, "max_cc") or 0) > 50:
        return [f"{stage.id}: a function exceeds 50 cyclomatic complexity"]
    if stage.category == "duplication" and (number(stage, "duplication_percent") or 0) > 60:
        return [f"{stage.id}: duplication exceeds 60%"]
    checks = stage.metrics.get("checks")
    if (
        stage.category == "hygiene"
        and isinstance(checks, dict)
        and checks.get("license_file") is False
    ):
        return [f"{stage.id}: no license file observed; adoption terms need review"]
    return []


def blockers(stages: list[StageResult]) -> list[str]:
    result = []
    for stage in stages:
        result.extend(metric_blockers(stage))
        result.extend(
            f"{stage.id}: {finding.rule} ({finding.path}:{finding.line})"
            for finding in stage.findings
            if finding.severity == "critical"
        )
    return sorted(set(result))
