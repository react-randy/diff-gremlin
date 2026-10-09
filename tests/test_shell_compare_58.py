"""Native Shell controls for the globally applied comparison blocker policy."""

import shutil
from dataclasses import replace

import pytest
from test_complexity_identity_58 import context

from diff_gremlin.analyzers.shell import analyze_shell_complexity
from diff_gremlin.analyzers.shell.decisions import MEASURE
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.sources import SourceIdentity
from diff_gremlin.policy.assessment import assess
from diff_gremlin.policy.comparison import comparison_exit_code
from diff_gremlin.policy.gates import Gates
from diff_gremlin.reporting.delta import compare_document


def function(name, value):
    return (
        f"{name}() {{\n"
        + "".join("if true; then :; fi\n" for _ in range(value - 1))
        + ":;\n}\n"
    )


def stage(directory, source):
    if not shutil.which("shfmt"):
        pytest.skip("native Shell comparison controls need pinned shfmt")
    result = analyze_shell_complexity(
        context(directory, "example.sh", "#!/bin/bash\n" + source, "shell")
    )
    assert result.status == "ok", result.reason
    return result


def compare(before, after):
    def report(observation, revision):
        return ScanReport(
            SourceIdentity("fixture", "fixture", revision * 40),
            "quick",
            ("shell",),
            [observation],
            assess([observation]),
            0,
        )

    base, head = report(before, "a"), report(after, "b")
    document = compare_document(base, head)
    return document, comparison_exit_code(base, head, document, Gates())


@pytest.mark.parametrize("value,expected", [(52, 0), (61, 1), (51, 0)])
def test_native_shell_local_growth_under_unchanged_maximum(tmp_path, value, expected):
    base = stage(tmp_path / "base", function("inherited", 113) + function("grown", 52))
    head = stage(
        tmp_path / "head", "\n\n" + function("inherited", 113) + function("grown", value)
    )
    document, code = compare(base, head)
    assert base.metrics["max_cc"] == head.metrics["max_cc"] == 113
    assert code == expected
    delta = document["deltas"][0]
    assert delta["added_findings"] == delta["resolved_findings"] == []
    assert {finding.metric for finding in head.findings} == {MEASURE}
    if value == 52:
        assert delta["unchanged_findings"] == 2 and not delta["changed_findings"]
    else:
        assert delta["changed_findings"][0]["measurement"] == {
            "metric": MEASURE,
            "base": 52,
            "head": value,
            "delta": value - 52,
        }
        assert document["delta_assessment"]["complete"] is True


def test_native_shell_new_blocker_is_not_hidden_by_inherited_maximum(tmp_path):
    base = stage(tmp_path / "base", function("inherited", 113))
    head = stage(tmp_path / "head", function("inherited", 113) + function("new", 51))
    document, code = compare(base, head)
    assert code == 1 and len(document["deltas"][0]["added_findings"]) == 1


def test_native_shell_partial_worsening_retains_known_blocker(tmp_path):
    base = stage(tmp_path / "base", function("inherited", 113) + function("grown", 52))
    head = stage(tmp_path / "head", function("inherited", 113) + function("grown", 61))
    document, code = compare(base, replace(head, status="limited", reason="Coverage gap"))
    assert code == 1 and document["delta_assessment"]["complete"] is False
    document, code = compare(
        replace(base, status="limited", reason="Coverage gap"),
        replace(base, status="limited", reason="Coverage gap"),
    )
    assert code == 3 and not document["delta_assessment"]["blockers"]


def test_native_shell_lexical_owners_and_dotted_names_do_not_collide(tmp_path):
    nested = "outer() {\n" + function("inner", 12) + ":;\n}\n"
    source = nested + function("outer.inner", 12)
    result = stage(tmp_path, source)
    assert {finding.symbol for finding in result.findings} == {
        "outer.inner",
        r"outer\.inner",
    }
    assert len({finding.fingerprint for finding in result.findings}) == 2


def test_native_shell_duplicate_changes_remain_uncertain(tmp_path):
    before = stage(
        tmp_path / "base",
        function("inherited", 113) + function("duplicate", 52) + function("duplicate", 55),
    )
    after = stage(
        tmp_path / "head",
        function("inherited", 113) + function("duplicate", 51) + function("duplicate", 56),
    )
    document, code = compare(before, after)
    assert code == 3 and document["deltas"][0]["ambiguous_identities"]
    assert not document["delta_assessment"]["blockers"]
