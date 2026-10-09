"""Full/compact stage coverage and conservative aggregate explanation."""

import json
from dataclasses import replace

import pytest
from test_compare_delta_58 import compared, complexity, measured
from test_reporting import report

from diff_gremlin.reporting.compact import delta_document
from diff_gremlin.reporting.delta import compare_document


@pytest.mark.parametrize("absent", ["base", "head", None])
@pytest.mark.parametrize("counts", [(0, 0), (4, 4), (2, 4)])
def test_full_and_compact_preserve_observed_stage_coverage(absent, counts):
    base = replace(complexity(), analyzed_files=3, eligible_files=5)
    head = replace(
        complexity(status="limited", reason="Partial inventory"),
        analyzed_files=counts[0],
        eligible_files=counts[1],
    )
    full = compare_document(
        report([] if absent == "base" else [base]),
        report([] if absent == "head" else [head]),
    )
    compact = json.loads(json.dumps(delta_document(full)))
    assert compact["deltas"] == full["deltas"]
    delta = compact["deltas"][0]
    assert delta["base_coverage"] == (
        None if absent == "base" else {"analyzed_files": 3, "eligible_files": 5}
    )
    assert delta["head_coverage"] == (
        None
        if absent == "head"
        else {"analyzed_files": counts[0], "eligible_files": counts[1]}
    )
    assert delta["head_status"] == ("absent" if absent == "head" else "limited")
    assert not delta["comparable"] and not delta["resolved_findings"]
    assert compact["delta_assessment"]["decision"] == "unknown"


def test_aggregate_rank_proof_does_not_claim_function_pairing():
    document, code = compared(
        complexity([measured(cc=61), measured(cc=52)]),
        complexity([measured(cc=62), measured(cc=51)]),
    )
    blockers = document["delta_assessment"]["blockers"]
    assert code == 1 and document["deltas"][0]["ambiguous_identities"]
    assert any(
        "sorted blocking-value distributions" in reason
        and "base 61, head 62" in reason
        and "function attribution is uncertain" in reason
        for reason in blockers
    )
    assert document["deltas"][0]["changed_findings"] == []
