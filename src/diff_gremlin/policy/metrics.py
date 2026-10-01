"""Translate observed metrics into category scores without inventing data."""

import math

from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.thresholds import (
    COMPLEXITY_BANDS,
    DUPLICATION_BANDS,
    LINT_BANDS,
    SEVERITY_PENALTIES,
    TYPE_BANDS,
    band_score,
)


def number(stage: StageResult, key: str) -> float | None:
    """Reject absent, boolean, negative and non-finite measurements."""
    value = stage.metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) and value >= 0 else None


def counted_score(
    stage: StageResult, key: str, bands: tuple[tuple[int, int], ...]
) -> int | None:
    value = number(stage, key)
    return None if value is None else band_score(value, bands)


def type_score(stage: StageResult) -> int | None:
    errors, warnings = number(stage, "error_count"), number(stage, "warning_count")
    if errors is None or warnings is None:
        return None
    return min(band_score(errors, TYPE_BANDS), band_score(warnings, LINT_BANDS))


def security_score(stage: StageResult) -> int:
    penalty = sum(SEVERITY_PENALTIES[finding.severity] for finding in stage.findings)
    return max(0, 100 - penalty)


def hygiene_score(stage: StageResult) -> int | None:
    checks = stage.metrics.get("checks")
    if not isinstance(checks, dict):
        return None
    required = ("license_file", "nontrivial_readme", "test_files", "gitignore_file")
    if any(not isinstance(checks.get(key), bool) for key in required):
        return None
    return 25 * sum(checks[key] for key in required)


def stage_score(stage: StageResult) -> int | None:
    """Incomplete stages never supply a score, even with useful findings."""
    if stage.status != "ok":
        return None
    scorers = {
        "lint": lambda: counted_score(stage, "issue_count", LINT_BANDS),
        "types": lambda: type_score(stage),
        "complexity": lambda: counted_score(stage, "max_cc", COMPLEXITY_BANDS),
        "duplication": lambda: counted_score(
            stage, "duplication_percent", DUPLICATION_BANDS
        ),
        "security": lambda: security_score(stage),
        "hygiene": lambda: hygiene_score(stage),
    }
    scorer = scorers.get(stage.category)
    return scorer() if scorer is not None else None
