"""Aggregate stable categories and retain honest measurement coverage."""

from diff_gremlin.domain.assessment import Assessment
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.blockers import blockers
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.policy.thresholds import WEIGHTS, grade


def selected_category(stages: list[StageResult], category: str) -> list[StageResult]:
    return [
        stage
        for stage in stages
        if stage.category == category and stage.required and stage.id != "inventory"
    ]


def worst_score(stages: list[StageResult]) -> int | None:
    scores = [stage_score(stage) for stage in stages]
    if None in scores:
        return None
    return min(score for score in scores if score is not None)


def category_scores(stages: list[StageResult]) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    for category in WEIGHTS:
        selected = selected_category(stages, category)
        if not selected:
            continue
        result[category] = worst_score(selected)
    return result


def coverage_gaps(stages: list[StageResult]) -> tuple[str, ...]:
    return tuple(
        stage.id
        for stage in stages
        if stage.required
        and (
            stage.status != "ok"
            or (
                stage.category in WEIGHTS
                and stage.id != "inventory"
                and stage_score(stage) is None
            )
        )
    )


def weighted_score(categories: dict[str, int | None], complete: bool) -> float | None:
    if not complete or not categories:
        return None
    denominator = sum(WEIGHTS[category] for category in categories)
    numerator = sum(
        WEIGHTS[category] * score
        for category, score in categories.items()
        if score is not None
    )
    return round(numerator / denominator, 2)


def decision_for(stages: list[StageResult], complete: bool, reasons: list[str]) -> str:
    if reasons:
        return "hold"
    if not complete:
        return "unknown"
    if any(
        f.severity in {"medium", "high"} for stage in stages for f in stage.findings
    ):
        return "review"
    return "no_configured_blockers"


def assess(stages: list[StageResult]) -> Assessment:
    categories = category_scores(stages)
    gaps = coverage_gaps(stages)
    required = sum(stage.required for stage in stages)
    complete = bool(required) and not gaps
    score = weighted_score(categories, complete)
    reasons = blockers(stages)
    if reasons and score is not None:
        score = min(score, 20)
    return Assessment(
        score,
        grade(score),
        categories,
        complete,
        required,
        required - len(gaps),
        gaps,
        tuple(reasons),
        decision_for(stages, complete, reasons),
    )
