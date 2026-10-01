"""The policy decision attached to an evidence receipt."""

from dataclasses import dataclass


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
