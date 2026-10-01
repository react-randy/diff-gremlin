"""The policy decision attached to an evidence receipt."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ObservedAssessment:
    """A provisional score from validated checks, never a CI approval."""

    score: float | None
    grade: str
    categories: dict[str, int]
    contributing_weight: int
    applicable_weight: int
    partial_categories: tuple[str, ...]
    contributing_stages: tuple[str, ...]
    excluded_stages: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Assessment:
    score: float | None
    grade: str
    categories: dict[str, int | None]
    complete: bool
    required_stages: int
    completed_stages: int
    gaps: tuple[str, ...]
    blockers: tuple[str, ...]
    decision: str
    observed: ObservedAssessment | None = None
