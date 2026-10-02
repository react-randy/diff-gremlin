"""Independent, published calibration for policy v1."""

POLICY_VERSION = "1.1.0"
WEIGHTS = {
    "lint": 15,
    "types": 20,
    "complexity": 20,
    "duplication": 15,
    "security": 20,
    "hygiene": 10,
}
LINT_BANDS = ((0, 100), (5, 90), (20, 75), (50, 60), (100, 40))
TYPE_BANDS = ((0, 100), (3, 90), (10, 75), (30, 50), (100, 25))
COMPLEXITY_BANDS = ((10, 100), (20, 85), (30, 70), (40, 50), (50, 30))
DUPLICATION_BANDS = ((5, 100), (10, 90), (20, 75), (40, 55), (60, 30))
SEVERITY_PENALTIES = {"info": 0, "low": 2, "medium": 8, "high": 25, "critical": 100}


def band_score(value: float, bands: tuple[tuple[int, int], ...]) -> int:
    """Use inclusive upper bounds; exceeding the last band scores zero."""
    for ceiling, score in bands:
        if value <= ceiling:
            return score
    return 0


def grade(score: float | None) -> str:
    """Unknown is distinct from a failing measurement."""
    if score is None:
        return "?"
    return next(
        (
            label
            for floor, label in ((90, "A"), (80, "B"), (70, "C"), (60, "D"))
            if score >= floor
        ),
        "F",
    )
