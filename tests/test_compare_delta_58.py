"""Independent controls for diff decisions, measurement changes and ambiguity."""

from dataclasses import replace

import pytest

from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.sources import SourceIdentity
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.assessment import assess
from diff_gremlin.policy.comparison import comparison_exit_code
from diff_gremlin.policy.gates import Gates
from diff_gremlin.reporting.delta import compare_document


def measured(name="Example.choose", cc=52, line=2):
    return Finding(
        "native.high-complexity",
        f"Native complexity is {cc}",
        "high" if cc > 50 else "medium",
        "example.ts",
        line,
        symbol=name,
        fingerprint=name,
        metric="cyclomatic_complexity",
        value=cc,
    )


def complexity(findings=(), maximum=113, status="ok", reason="", version="1"):
    return StageResult(
        "complexity.javascript",
        "Native function complexity",
        "complexity",
        status,
        "native",
        version,
        metrics={"max_cc": maximum},
        findings=list(findings),
        reason=reason,
    )


def report(stage, revision="a"):
    return ScanReport(
        SourceIdentity("fixture", "fixture", revision * 40),
        "full",
        ("typescript",),
        [stage],
        assess([stage]),
        0,
    )


def compared(base, head, gates=None, **maps):
    before, after = report(base), report(head, "b")
    document = compare_document(before, after, **maps)
    return document, comparison_exit_code(before, after, document, gates or Gates())


def test_moved_inherited_blocker_is_unchanged_and_default_passes():
    document, code = compared(complexity([measured()]), complexity([measured(line=40)]))
    delta = document["deltas"][0]
    assert delta["added_findings"] == delta["resolved_findings"] == []
    assert delta["changed_findings"] == [] and delta["unchanged_findings"] == 1
    assert document["base"]["assessment"]["decision"] == "hold"
    assert document["head"]["assessment"]["decision"] == "hold"
    assert document["delta_assessment"]["decision"] == "no_configured_regressions"
    assert code == 0


def test_grown_existing_blocker_is_measured_even_if_maximum_stays_113():
    document, code = compared(complexity([measured()]), complexity([measured(cc=61)]))
    delta = document["deltas"][0]
    assert delta["added_findings"] == delta["resolved_findings"] == []
    assert delta["changed_findings"][0]["measurement"] == {
        "metric": "cyclomatic_complexity",
        "base": 52,
        "head": 61,
        "delta": 9,
    }
    assert document["delta_assessment"]["decision"] == "hold" and code == 1


@pytest.mark.parametrize("cc,expected", [(11, 0), (51, 1)])
def test_new_function_respects_existing_blocker_threshold(cc, expected):
    document, code = compared(complexity(), complexity([measured("new", cc)]))
    assert len(document["deltas"][0]["added_findings"]) == 1 and code == expected


def test_same_blocker_and_incomplete_evidence_is_unknown_three():
    base = complexity([measured()], status="limited", reason="Coverage incomplete")
    document, code = compared(base, replace(base))
    delta = document["deltas"][0]
    assert not delta["comparable"] and not delta["resolved_findings"]
    assert delta["base_reason"] == delta["head_reason"] == "Coverage incomplete"
    assert document["delta_assessment"]["decision"] == "unknown" and code == 3


@pytest.mark.parametrize("gates", [Gates(fail_on="critical"), Gates(fail_under=0)])
def test_explicit_gates_preserve_full_head_policy_including_inherited_blockers(gates):
    _, code = compared(complexity([measured()]), complexity([measured()]), gates)
    assert code == 1


def test_require_complete_keeps_default_comparison_behavior():
    _, code = compared(
        complexity([measured()]), complexity([measured()]), Gates(require_complete=True)
    )
    assert code == 0
    _, code = compared(
        complexity(status="limited"), complexity(), Gates(require_complete=True)
    )
    assert code == 3


def test_unknown_head_cannot_resolve_or_hide_changed_observations():
    document, code = compared(
        complexity([measured()]), complexity([measured(cc=61)], status="limited")
    )
    delta = document["deltas"][0]
    assert delta["resolved_findings"] == delta["changed_findings"] == []
    assert delta["added_findings"][0]["value"] == 61 and code == 1


def test_tool_version_change_is_unknown_without_numeric_or_resolution_claims():
    document, code = compared(complexity([measured()]), complexity(version="2"))
    delta = document["deltas"][0]
    assert not delta["comparable"] and delta["metrics"] == {}
    assert (
        delta["resolved_findings"] == []
        and "same tool and version" in delta["resolution_note"]
    )
    assert code == 3


def test_qualified_names_with_same_short_name_match_separately():
    before = complexity([measured("First.choose"), measured("Second.choose")])
    after = complexity(
        [measured("Second.choose", line=30), measured("First.choose", line=40)]
    )
    document, code = compared(before, after)
    assert document["deltas"][0]["unchanged_findings"] == 2 and code == 0


def test_duplicate_changes_are_visible_without_false_regression_or_resolution():
    before = complexity([measured(cc=61), measured(cc=60)])
    after = complexity([measured(cc=59), measured(cc=55)])
    document, code = compared(before, after)
    delta = document["deltas"][0]
    assert len(delta["added_findings"]) == 2 and delta["changed_findings"] == []
    assert delta["resolved_findings"] == [] and delta["ambiguous_identities"]
    assert not document["delta_assessment"]["blockers"] and code == 3


def test_duplicate_multiplicity_is_accounted_for_without_location_pairing():
    before = complexity([measured(line=1), measured(line=2)])
    after = complexity([measured(line=40), measured(line=41)])
    document, code = compared(before, after)
    delta = document["deltas"][0]
    assert delta["unchanged_findings"] == 2 and not delta["ambiguous_identities"]
    assert delta["added_findings"] == delta["resolved_findings"] == [] and code == 0


def test_hunk_flags_use_their_own_snapshot_and_unknown_is_null():
    before = complexity([measured(line=2), measured("removed", line=7)])
    after = complexity([measured(cc=61, line=10), measured("added", cc=11, line=20)])
    document, _ = compared(
        before,
        after,
        base_changed_lines={"example.ts": ((2, 2),)},
        head_changed_lines={"example.ts": ((19, 21),)},
    )
    delta = document["deltas"][0]
    change = delta["changed_findings"][0]
    assert change["base"]["in_changed_lines"] is True
    assert change["head"]["in_changed_lines"] is False
    assert delta["added_findings"][0]["in_changed_lines"] is True
    assert delta["resolved_findings"][0]["in_changed_lines"] is False
    document, _ = compared(complexity(), complexity([measured()]))
    assert document["deltas"][0]["added_findings"][0]["in_changed_lines"] is None


def test_unlocated_hunk_evidence_is_null_and_explicit_empty_map_is_false():
    document, _ = compared(
        complexity(), complexity([measured(line=0)]), head_changed_lines={}
    )
    assert document["deltas"][0]["added_findings"][0]["in_changed_lines"] is None
    document, _ = compared(
        complexity(), complexity([measured()]), head_changed_lines={}
    )
    assert document["deltas"][0]["added_findings"][0]["in_changed_lines"] is False


def test_severity_crossing_to_critical_is_changed_and_blocks():
    old = Finding("rule", "Review evidence", "high", "a.txt", 1, fingerprint="stable")
    new = replace(old, severity="critical", line=40)
    before = StageResult(
        "security", "Security", "security", "ok", "fixture", findings=[old]
    )
    after = replace(before, findings=[new])
    document, code = compared(before, after)
    delta = document["deltas"][0]
    assert not delta["added_findings"] and delta["changed_findings"][0]["severity"] == {
        "base": "high",
        "head": "critical",
    }
    assert code == 1


@pytest.mark.parametrize(
    "category,key,before,after",
    [
        ("complexity", "max_cc", 113, 114),
        ("duplication", "duplication_percent", 60, 61),
    ],
)
def test_numeric_blocking_worsening_without_findings_is_still_proven(
    category, key, before, after
):
    base = StageResult(
        "metric", "Metric", category, "ok", "fixture", metrics={key: before}
    )
    head = replace(base, metrics={key: after})
    document, code = compared(base, head)
    assert document["delta_assessment"]["blockers"] and code == 1
    assert (
        document["delta_assessment"]["regressions"]
        and not document["delta_assessment"]["unchanged"]
    )
    document, code = compared(head, base)
    assert document["delta_assessment"]["improvements"] and code == 0


def test_license_removed_is_a_new_blocker_and_improvement_remains_visible():
    checks = dict.fromkeys(
        ("license_file", "nontrivial_readme", "test_files", "gitignore_file"), True
    )
    base = StageResult(
        "hygiene", "Hygiene", "hygiene", "ok", "fixture", metrics={"checks": checks}
    )
    head = replace(base, metrics={"checks": {**checks, "license_file": False}})
    document, code = compared(base, head)
    assert document["delta_assessment"]["blockers"] and code == 1
    document, code = compared(
        complexity([measured(cc=61)]), complexity([measured(cc=52)])
    )
    assert document["delta_assessment"]["improvements"] and code == 0


@pytest.mark.parametrize(
    "attribute,value", [("scope", "other subset"), ("tool", "another analyzer")]
)
def test_different_analysis_scope_or_tool_cannot_prove_a_regression(attribute, value):
    base = complexity([measured()])
    head = replace(complexity([measured(cc=61)]), **{attribute: value})
    document, code = compared(base, head)
    assert not document["deltas"][0]["comparable"] and code == 3


def test_different_profiles_are_unknown_even_with_the_same_tool():
    before, after = (
        report(complexity([measured()])),
        report(complexity([measured(cc=61)])),
    )
    after = replace(after, profile="quick")
    document = compare_document(before, after)
    assert not document["deltas"][0]["comparable"]
    assert comparison_exit_code(before, after, document, Gates()) == 3


def test_nonrequired_history_gap_does_not_make_complete_comparison_incomplete():
    stage = complexity([measured()])
    optional = StageResult(
        "history", "History", "history", "unsupported", "fixture", required=False
    )
    stages = [stage, optional]
    base = replace(report(stage), stages=stages, assessment=assess(stages))
    head = replace(base, source=SourceIdentity("fixture", "fixture", "b" * 40))
    document = compare_document(base, head)
    assert document["delta_assessment"]["unknown"]
    assert document["delta_assessment"]["complete"]
    assert comparison_exit_code(base, head, document, Gates()) == 0


def test_changed_anonymous_body_at_the_same_complexity_does_not_invent_a_blocker():
    old = replace(measured(), fingerprint="old-body", identity_kind="body")
    new = replace(old, fingerprint="new-body", line=40)
    document, code = compared(complexity([old]), complexity([new]))
    delta = document["deltas"][0]
    assert delta["uncertain_identities"] == ["new-body"]
    assert len(delta["added_findings"]) == len(delta["resolved_findings"]) == 1
    assert not document["delta_assessment"]["blockers"] and code == 3


def test_partial_new_critical_finding_is_known_only_against_complete_base():
    old = StageResult("security", "Security", "security", "ok", "fixture")
    finding = Finding(
        "critical.rule", "Native dangerous evidence", "critical", "a.txt", 1
    )
    new = replace(old, status="limited", findings=[finding])
    document, code = compared(old, new)
    assert document["delta_assessment"]["decision"] == "hold" and code == 1
    document, code = compared(replace(old, status="limited"), new)
    assert document["delta_assessment"]["decision"] == "unknown" and code == 3


@pytest.mark.parametrize("head_status", ["ok", "limited"])
def test_duplicate_critical_count_increase_is_proven_despite_pairing(head_status):
    finding = Finding("critical.rule", "Critical evidence", "critical", "a.txt", 1)
    before = StageResult(
        "security", "Security", "security", "ok", "fixture", findings=[finding]
    )
    after = replace(before, status=head_status, findings=[finding, replace(finding, line=3)])
    document, code = compared(before, after)
    assert code == 1 and document["deltas"][0]["ambiguous_identities"]
    assert any("critical observation count increased from 1 to 2" in x for x in document["delta_assessment"]["blockers"])
    document, code = compared(replace(before, status="limited"), after)
    assert code == 3 and not document["delta_assessment"]["blockers"]


@pytest.mark.parametrize(
    "old,new,expected",
    [
        ([51, 100], [90], 3),
        ([52, 52], [52, 52, 52], 1),
        ([52, 55], [51, 56], 1),
        ([52, 55], [51, 54], 3),
        ([52, 55], [55, 52], 0),
    ],
)
def test_aggregate_blocking_values_preserve_descending_dominance(old, new, expected):
    before = complexity([measured(cc=value) for value in old])
    after = complexity([measured(cc=value) for value in new])
    document, code = compared(before, after)
    assert code == expected
    assert bool(document["delta_assessment"]["blockers"]) == (expected == 1)


def test_aggregate_measures_are_compared_separately():
    before = complexity(
        [measured(cc=100), replace(measured(cc=51), metric="shell-ast-decision-complexity-v1")]
    )
    after = complexity([replace(measured(cc=90), metric="shell-ast-decision-complexity-v1")])
    document, code = compared(before, after)
    assert code == 1
    assert any("shell-ast-decision-complexity-v1" in x for x in document["delta_assessment"]["blockers"])


@pytest.mark.parametrize("incompatible", ["tool", "profile"])
def test_incompatible_observations_cannot_prove_aggregate_surplus(incompatible):
    before = report(complexity([measured(), measured()]))
    after = report(complexity([measured(), measured(), measured()]), "b")
    if incompatible == "tool":
        after = replace(after, stages=[replace(after.stages[0], tool="other")])
    else:
        after = replace(after, profile="quick")
    document = compare_document(before, after)
    assert comparison_exit_code(before, after, document, Gates()) == 3
    assert not document["delta_assessment"]["blockers"]
