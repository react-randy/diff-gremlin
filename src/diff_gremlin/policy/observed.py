"""Score measured evidence while keeping missing checks explicit."""

from diff_gremlin.domain.assessment import ObservedAssessment
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.policy.thresholds import WEIGHTS, grade


def _measurements(stages: list[StageResult]):
    """Record validated category values and the stages excluded from them."""
    categories: dict[str, int] = {}
    contributors, exclusions = [], []
    partial = set()
    for stage in stages:
        score = stage_score(stage)
        if score is None:
            exclusions.append(stage.id)
            partial.add(stage.category)
            continue
        contributors.append(stage.id)
        categories[stage.category] = min(categories.get(stage.category, 100), score)
    return categories, contributors, exclusions, partial


def _weighted_score(categories: dict[str, int], weight: int, blocked: bool):
    """Calculate the provisional mean and retain known blocker penalties."""
    if not weight:
        return None
    score = round(
        sum(WEIGHTS[key] * value for key, value in categories.items()) / weight, 2
    )
    return min(score, 20) if blocked else score


def observed_assessment(
    stages: list[StageResult], *, blocked: bool
) -> ObservedAssessment:
    """Use the worst validated stage per category and disclose its coverage."""
    selected = [
        stage
        for stage in stages
        if stage.required and stage.id != "inventory" and stage.category in WEIGHTS
    ]
    categories, contributors, exclusions, partial = _measurements(selected)
    weight = sum(WEIGHTS[category] for category in categories)
    applicable = sum(WEIGHTS[category] for category in {s.category for s in selected})
    score = _weighted_score(categories, weight, blocked)
    return ObservedAssessment(
        score,
        grade(score),
        categories,
        weight,
        applicable,
        tuple(sorted(partial)),
        tuple(contributors),
        tuple(exclusions),
    )
