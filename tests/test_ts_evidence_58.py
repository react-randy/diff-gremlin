"""Native compiler context, environment aggregation and private source controls."""

import json

import pytest
import test_polyglot

from diff_gremlin.analyzers.javascript.output import (
    diagnostic_message,
    located_findings,
)
from diff_gremlin.analyzers.javascript.types import analyze_ts_types
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.process import run

context = test_polyglot.context


def test_native_ts_environment_aggregates_while_source_errors_keep_messages(context):
    source = 'import React from "@scope/package";\nexport function Example(value) { return <div>{value.nonexistent}</div>; }\nexport const n: number = "wrong";\nconst sample = {}; sample.absent;\n'
    ctx = context([("Example.tsx", "typescript", source)], run)
    stage = analyze_ts_types(ctx)
    assert stage.status == "limited", stage.reason
    assert stage.metrics["environment_diagnostics"] == {"TS2307": 1, "TS7026": 2}
    assert stage.metrics["environment_count"] == 3
    assert stage.metrics["source_error_count"] == 3
    assert {finding.rule for finding in stage.findings} == {
        "TS7006",
        "TS2322",
        "TS2339",
    }
    assert any("Parameter 'value'" in finding.message for finding in stage.findings)
    assert any("Property 'absent'" in finding.message for finding in stage.findings)
    assert any(
        "Type 'string' is not assignable to type 'number'" in finding.message
        for finding in stage.findings
    )
    assert "@scope/package" in stage.metrics["environment_examples"]["TS2307"]
    assert "JSX.IntrinsicElements" in stage.metrics["environment_examples"]["TS7026"]
    assert stage_score(stage) is None
    assert ctx.files[0].path.read_text() == source


@pytest.mark.parametrize(
    "literal",
    [
        "short-secret",
        "alpha'beta'delta",
        "ghp_" + "x" * 40,
        "line\\nprivate",
        "`[secret](https://example.invalid)`",
    ],
)
def test_native_ts_literal_values_remain_private_even_with_nested_quotes(
    context, literal
):
    source = 'export const value: "acceptable" = ' + json.dumps(literal) + ";\n"
    stage = analyze_ts_types(context([("literal.ts", "typescript", source)], run))
    assert stage.status == "ok", stage.reason
    assert len(stage.findings) == 1 and stage.findings[0].rule == "TS2322"
    message = stage.findings[0].message
    assert "is not assignable to type" in message and "redacted" in message
    assert literal not in message and "acceptable" not in message
    assert "beta" not in message and "private" not in message


def test_diagnostic_sanitizer_bounds_controls_credentials_paths_and_markup(monkeypatch):
    monkeypatch.setenv("ISSUE58_API_TOKEN", "environment-secret")
    text = (
        "Property 'field' does not exist on type '{}'. environment-secret /tmp/scratch/private.ts C:\\private\\source.ts ghp_"
        + "x" * 40
        + "\x1b[31m\n# [link](https://host.invalid) <script>\u202e"
        + " safe" * 1000
    )
    message = diagnostic_message(text)
    assert "Property 'field'" in message and len(message) <= 512
    assert all(
        secret not in message
        for secret in (
            "environment-secret",
            "/tmp/",
            "C:\\private",
            "ghp_",
            "\x1b",
            "\n",
            "\u202e",
            "[link]",
            "<script>",
        )
    )
    assert (
        diagnostic_message(
            "Type '\"alpha'beta'delta\"' is not assignable to type 'number'."
        )
        == "Native diagnostic text withheld because quoting was unsafe"
    )


def test_other_adapters_keep_generic_diagnostic_messages(context):
    ctx = context([("a.js", "javascript", "missing;\n")])
    rows = [
        {
            "path": str(ctx.files[0].path.resolve()),
            "line": 1,
            "column": 1,
            "rule": "no-undef",
            "severity": "medium",
            "message": "secret source",
        }
    ]
    assert located_findings(rows, ctx.files)[0].message == "Review no-undef diagnostic"


def test_native_ts_token_shaped_identifiers_are_redacted(context):
    stage = analyze_ts_types(
        context(
            [("token.ts", "typescript", "export const value = ghp_SyntheticToken;\n")],
            run,
        )
    )
    assert stage.status == "ok" and stage.findings[0].rule == "TS2304"
    assert "Cannot find name" in stage.findings[0].message
    assert "ghp_SyntheticToken" not in stage.findings[0].message
