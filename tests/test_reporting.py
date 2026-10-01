"""Unknown evidence and source-controlled output remain visible and inert."""

from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.sources import SourceIdentity
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.assessment import assess
from diff_gremlin.reporting.delta import compare_document
from diff_gremlin.reporting.escaping import markdown, plain
from diff_gremlin.reporting.serialization import json_text, report_document


def report(stages):
    return ScanReport(
        SourceIdentity("fixture", "fixture", "a" * 40),
        "full",
        ("python",),
        stages,
        assess(stages),
        1,
    )


def test_missing_head_does_not_resolve_base_findings():
    base = StageResult(
        "lint.python",
        "Lint",
        "lint",
        "ok",
        "fixture",
        metrics={"issue_count": 1},
        findings=[Finding("bug", "Bug", path="x.py", line=1)],
    )
    head = StageResult("lint.python", "Lint", "lint", "missing", "fixture")
    delta = compare_document(report([base]), report([head]))["deltas"][0]
    assert not delta["comparable"] and delta["resolved_findings"] == []


def test_location_move_does_not_invent_resolution():
    before = Finding("bug", "Bug", path="x.py", line=1)
    after = Finding("bug", "Bug", path="x.py", line=100)
    a = StageResult(
        "lint",
        "Lint",
        "lint",
        "ok",
        "fixture",
        metrics={"issue_count": 1},
        findings=[before],
    )
    b = StageResult(
        "lint",
        "Lint",
        "lint",
        "ok",
        "fixture",
        metrics={"issue_count": 1},
        findings=[after],
    )
    delta = compare_document(report([a]), report([b]))["deltas"][0]
    assert delta["added_findings"] == delta["resolved_findings"] == []


def test_machine_receipt_keeps_unknown_and_every_stage():
    stage = StageResult(
        "types", "Types", "types", "timeout", "fixture", reason="Deadline"
    )
    document = report_document(report([stage]))
    assert document["assessment"]["score"] is None
    assert document["stages"][0]["status"] == "timeout"
    assert '"score": null' in json_text(document)


def test_terminal_and_markdown_injection_are_neutralized():
    assert "\x1b" not in plain("bad\x1b[31m")
    assert "\\|" in markdown("x|y")
    assert "\\<" in markdown("<script>")
