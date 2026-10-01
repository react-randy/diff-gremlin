"""Score measured evidence while keeping missing checks explicit."""

from diff_gremlin.domain.assessment import ObservedAssessment
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.policy.thresholds import WEIGHTS, grade


def observed_assessment(
    stages: list[StageResult], *, blocked: bool
) -> ObservedAssessment:
    """Use the worst validated stage per category and disclose its coverage."""
    selected = [
        stage
        for stage in stages
        if stage.required and stage.id != "inventory" and stage.category in WEIGHTS
    ]
    categories: dict[str, int] = {}
    contributors, exclusions = [], []
    partial = set()
    for stage in selected:
        score = stage_score(stage)
        if score is None:
            exclusions.append(stage.id)
            partial.add(stage.category)
            continue
        contributors.append(stage.id)
        categories[stage.category] = min(categories.get(stage.category, 100), score)
    weight = sum(WEIGHTS[category] for category in categories)
    applicable = sum(WEIGHTS[category] for category in {s.category for s in selected})
    score = (
        round(
            sum(WEIGHTS[key] * value for key, value in categories.items()) / weight, 2
        )
        if weight
        else None
    )
    if blocked and score is not None:
        score = min(score, 20)
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
