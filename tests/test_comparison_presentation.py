"""Reviewers can see changes and distinguish missing evidence from resolutions."""

from dataclasses import replace

import pytest

from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.sources import SourceIdentity
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.assessment import assess
from diff_gremlin.reporting.comparison import render
from diff_gremlin.reporting.delta import compare_document


def receipt(stage: StageResult, revision: str) -> ScanReport:
    return ScanReport(
        SourceIdentity("fixture", "fixture", revision * 40),
        "full",
        ("python",),
        [stage],
        assess([stage]),
        1,
    )


def lint(findings: list[Finding]) -> StageResult:
    return StageResult(
        "lint.python",
        "Python lint",
        "lint",
        "ok",
        "fixture",
        metrics={"issue_count": len(findings)},
        findings=findings,
        eligible_files=1,
        analyzed_files=1,
    )


@pytest.mark.parametrize("format", ["text", "markdown"])
def test_review_shows_scores_coverage_and_located_numeric_changes(format):
    base = receipt(lint([Finding("old", "Old issue", path="old.py", line=7)]), "a")
    head = receipt(
        lint(
            [
                Finding("new", "New issue", "high", "new.py", 11, 3),
                Finding("another", "Another issue", path="new.py", line=12),
            ]
        ),
        "b",
    )
    output = render(compare_document(base, head), head, format=format)
    assert "Base: " + "a" * 40 in output and "Head: " + "b" * 40 in output
    assert "1/1 required stages" in output and "90/100" in output
    assert "issue" in output and "+1" in output
    assert "new.py:11:3" in output and "old.py:7:0" in output
    assert output.index("new.py:11:3") < output.index("new.py:12:0")
    assert (
        "Confirmed resolutions" in output and "Complete head receipt follows" in output
    )
    if format == "markdown":
        assert "## Changed metrics" in output and "| Stage | Metric |" in output
        assert "| issue\\_count | 1 | 2 | +1 |" in output


@pytest.mark.parametrize("format", ["text", "markdown"])
def test_unknown_head_does_not_claim_resolution_or_numeric_improvement(format):
    base = receipt(lint([Finding("old", "Old issue", path="old.py", line=7)]), "a")
    head = receipt(replace(lint([]), status="missing", reason="Tool absent"), "b")
    output = render(compare_document(base, head), head, format=format)
    assert "unknown" in output and "0/1 required stages" in output
    assert "Resolution requires complete observations on both sides" in output
    assert "No numeric changes in stages with complete evidence" in output
    assert "-1 confirmed" not in output


@pytest.mark.parametrize("format", ["text", "markdown"])
def test_untrusted_comparison_text_cannot_control_terminal_or_markdown(format):
    base = receipt(lint([]), "a")
    head = receipt(
        lint([Finding("rule|x", "```\n<script>\x1b[31m", "high", "x|y.py", 2)]), "b"
    )
    output = render(compare_document(base, head), head, format=format)
    assert "\x1b" not in output and "\\u001b" in output
    if format == "markdown":
        assert "x\\|y.py" in output and "\\<script\\>" in output
        assert "\n<script>" not in output and "\n```" not in output
