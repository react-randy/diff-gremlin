"""Provisional results help readers without approving missing evidence."""

import pytest

from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.sources import SourceIdentity
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.assessment import assess
from diff_gremlin.policy.gates import Gates, exit_code
from diff_gremlin.reporting import markdown, text
from diff_gremlin.reporting.serialization import report_document


def lint(identifier, status="ok", issues=0):
    return StageResult(
        identifier, "Lint", "lint", status, "fixture", metrics={"issue_count": issues}
    )


def test_partial_score_uses_validated_evidence_without_approving_ci():
    stages = [
        lint("python.lint", issues=6),
        lint("javascript.lint", "failed", issues=0),
        StageResult(
            "types",
            "Types",
            "types",
            "limited",
            "fixture",
            metrics={"error_count": 0, "warning_count": 0},
        ),
        StageResult(
            "complexity",
            "Complexity",
            "complexity",
            "ok",
            "fixture",
            metrics={"max_cc": 15},
        ),
    ]
    assessment = assess(stages)
    observed = assessment.observed
    assert observed is not None
    # Independently: (15 * 75 + 20 * 85) / 35, applicable weight 55.
    assert observed.score == 80.71
    assert observed.categories == {"lint": 75, "complexity": 85}
    assert (observed.contributing_weight, observed.applicable_weight) == (35, 55)
    assert observed.partial_categories == ("lint", "types")
    assert observed.excluded_stages == ("javascript.lint", "types")
    assert assessment.score is None and not assessment.complete
    assert exit_code(assessment, stages, Gates(fail_under=1)) == 3


@pytest.mark.parametrize(
    "status", ["missing", "failed", "limited", "timeout", "unsupported", "skipped"]
)
def test_unavailable_tool_does_not_supply_an_observed_pass(status):
    observed = assess([lint("lint", status)]).observed
    assert observed is not None and observed.score is None
    assert observed.contributing_weight == 0
    assert observed.contributing_stages == ()


def test_invalid_metrics_and_optional_stages_do_not_contribute():
    stages = [lint("invalid", issues=float("nan")), lint("optional")]
    stages[1].required = False
    observed = assess(stages).observed
    assert observed is not None and observed.score is None


def test_known_blocker_caps_provisional_score_and_remains_gate_failure():
    stages = [
        lint("lint"),
        StageResult(
            "security",
            "Security",
            "security",
            "limited",
            "fixture",
            findings=[Finding("critical", "Observed blocker", "critical")],
        ),
    ]
    assessment = assess(stages)
    assert assessment.observed is not None and assessment.observed.score == 20
    assert assessment.score is None and assessment.decision == "hold"
    assert exit_code(assessment, stages, Gates()) == 1


def test_complete_observed_and_strict_scores_agree():
    assessment = assess([lint("lint", issues=5)])
    assert assessment.observed is not None
    assert assessment.observed.score == assessment.score == 90


def test_human_headline_labels_partial_evidence_and_json_preserves_all_findings():
    stages = [
        lint("lint", issues=50),
        StageResult("types", "Types", "types", "missing", "fixture"),
    ]
    stages[0].findings = [
        Finding(f"rule-{i}", "Diagnostic", path="source.py", line=i + 1)
        for i in range(25)
    ]
    report = ScanReport(
        SourceIdentity("fixture", "fixture"),
        "quick",
        ("python",),
        stages,
        assess(stages),
        1,
    )
    for output in (text.render(report), markdown.render(report)):
        assert "observed 60/100 (D)" in output and "provisional" in output
        assert "strict score unknown" in output
        assert "weight 15/35" in output
        assert "Showing 20 of 25 findings" in output
    receipt = report_document(report)
    assert receipt["assessment"]["score"] is None
    assert receipt["assessment"]["observed"]["score"] == 60
    assert len(receipt["stages"][0]["findings"]) == 25
