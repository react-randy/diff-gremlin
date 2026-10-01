"""Independent clean, bad and unavailable calibration controls."""

import pytest

from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.assessment import assess
from diff_gremlin.policy.gates import Gates, exit_code
from diff_gremlin.policy.metrics import stage_score


def stage(category, metrics=None, **kwargs):
    return StageResult(
        f"fixture.{category}",
        category,
        category,
        "ok",
        "fixture",
        metrics=metrics or {},
        **kwargs,
    )


def clean_stages():
    return [
        stage("lint", {"issue_count": 0}),
        stage("types", {"error_count": 0, "warning_count": 0}),
        stage("complexity", {"max_cc": 2}),
        stage("duplication", {"duplication_percent": 0}),
        stage("security"),
        stage(
            "hygiene",
            {
                "checks": dict.fromkeys(
                    (
                        "license_file",
                        "nontrivial_readme",
                        "test_files",
                        "gitignore_file",
                    ),
                    True,
                )
            },
        ),
    ]


def test_clean_independent_fixture_can_earn_one_hundred():
    result = assess(clean_stages())
    assert (result.score, result.grade, result.complete, result.decision) == (
        100,
        "A",
        True,
        "no_configured_blockers",
    )


@pytest.mark.parametrize(
    "status", ["missing", "failed", "timeout", "limited", "unsupported", "skipped"]
)
def test_missing_measurement_is_never_clean(status):
    stages = clean_stages()
    stages[0].status = status
    result = assess(stages)
    assert result.score is None and not result.complete
    assert exit_code(result, stages, Gates(fail_under=90)) == 3


def test_nan_and_missing_metrics_cannot_supply_score():
    assert stage_score(stage("lint", {"issue_count": float("nan")})) is None
    assert stage_score(stage("complexity")) is None


def test_critical_still_blocks_with_missing_evidence():
    stages = clean_stages()
    stages[0].status = "missing"
    stages[4].findings = [
        Finding("fixture.secret", "Potential credential", "critical", "config.txt", 1)
    ]
    result = assess(stages)
    assert result.score is None and result.decision == "hold"
    assert exit_code(result, stages, Gates()) == 1


def test_mixed_language_category_retains_worst_signal():
    stages = clean_stages()
    stages.append(stage("types", {"error_count": 12, "warning_count": 0}))
    assert assess(stages).categories["types"] == 50


def test_informational_health_does_not_double_count():
    stages = [*clean_stages(), stage("health", {"health_score": 0}, required=False)]
    assert assess(stages).score == 100


def test_license_and_extreme_complexity_block():
    stages = clean_stages()
    stages[2].metrics["max_cc"] = 51
    result = assess(stages)
    assert result.score == 20 and result.grade == "F"
    assert exit_code(result, stages, Gates()) == 1


def test_severity_and_numeric_gates_are_effective():
    stages = clean_stages()
    stages[4].findings = [Finding("fixture.eval", "Review dynamic execution", "high")]
    result = assess(stages)
    assert exit_code(result, stages, Gates(fail_on="high")) == 1
    assert exit_code(result, stages, Gates(fail_under=100)) == 1
