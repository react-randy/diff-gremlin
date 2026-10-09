"""Named receiver evidence remains useful without publishing native source fragments."""

import json
from dataclasses import replace

import pytest
import test_polyglot

from diff_gremlin.analyzers.javascript.output import (
    diagnostic_message,
    located_findings,
)
from diff_gremlin.analyzers.javascript.types import analyze_ts_types
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.sources import SourceIdentity
from diff_gremlin.policy.assessment import assess
from diff_gremlin.process import run
from diff_gremlin.reporting import comparison, markdown, text
from diff_gremlin.reporting.compact import delta_document
from diff_gremlin.reporting.delta import compare_document
from diff_gremlin.reporting.serialization import json_text, report_document

context = test_polyglot.context


def _report(stage):
    return ScanReport(
        SourceIdentity("fixture", "fixture", "a" * 40),
        "full",
        ("typescript",),
        [stage],
        assess([stage]),
        0,
    )


def test_native_ts_named_receiver_survives_producer_json_and_renderers(context):
    source = (
        "class Example_Type { present_field = 1; }\n"
        "export const example = new Example_Type();\n"
        "export const value = example.missing_field;\n"
        'export const bad: number = "wrong";\n'
    )
    native = []

    def observe(command, **kwargs):
        result = run(command, **kwargs)
        native.append(json.loads(result.stdout))
        return result

    ctx = context([("example.ts", "typescript", source)], observe)
    stage = analyze_ts_types(ctx)
    assert stage.status == "ok", stage.reason
    assert stage.version == "6.0.3"
    assert stage.metrics["source_error_count"] == 2
    assert stage.metrics["environment_count"] == 0
    messages = {finding.rule: finding.message for finding in stage.findings}
    expected = "Property 'missing_field' does not exist on type 'Example_Type'."
    assert messages["TS2339"] == expected
    assert messages["TS2322"] == "Type 'string' is not assignable to type 'number'."
    assert (
        next(row["message"] for row in native[0]["findings"] if row["rule"] == "TS2339")
        == expected
    )
    assert ctx.files[0].path.read_text() == source

    head = _report(stage)
    document = json.loads(json_text(report_document(head)))
    assert document["stages"][0]["findings"][0]["message"] == expected
    assert "\\" not in document["stages"][0]["findings"][0]["message"]
    escaped = "Property 'missing\\_field' does not exist on type 'Example\\_Type'."
    assert expected in text.render(head)
    assert escaped in markdown.render(head)
    assert "missing\\\\_field" not in markdown.render(head)

    base = _report(
        replace(
            stage,
            findings=[],
            metrics={**stage.metrics, "error_count": 0, "source_error_count": 0},
        )
    )
    delta = compare_document(base, head)
    for receipt in (delta, delta_document(delta)):
        parsed = json.loads(json_text(receipt))
        assert (
            next(
                row["message"]
                for row in parsed["deltas"][0]["added_findings"]
                if row["rule"] == "TS2339"
            )
            == expected
        )
    assert expected in comparison.render(delta, head, format="text")
    rendered = comparison.render(delta, head, format="markdown")
    assert escaped in rendered and "missing\\\\_field" not in rendered


@pytest.mark.parametrize(
    "receiver", ["ExampleType", "Example_Type", "ns.Example", "$Shape"]
)
def test_named_receiver_grammar_keeps_plain_identifiers(receiver):
    message = f"Property 'missing_field' does not exist on type '{receiver}'."
    assert diagnostic_message(message) == message


@pytest.mark.parametrize(
    "receiver",
    [
        "{ private_field: number; }",
        "string | PrivateType",
        "PrivateType<string>",
        "PrivateType[]",
        '"private-literal"',
        "/tmp/private/source.ts",
        "C:\\private\\source.ts",
        "ghp_SyntheticType",
        "x" * 80,
        "PrivateType\x00",
        "[private](https://example.invalid)",
    ],
)
def test_receiver_source_fragments_are_withheld(receiver):
    message = diagnostic_message(
        f"Property 'missing' does not exist on type '{receiver}'."
    )
    assert receiver not in message
    assert "redacted" in message or "withheld" in message
    assert "\\" not in message


def test_named_type_allowance_does_not_expand_other_type_contexts():
    assert diagnostic_message(
        "Type 'PrivateType' is not assignable to type 'Other'."
    ) == ("Type '[redacted]' is not assignable to type '[redacted]'.")
    assert diagnostic_message("Cannot find module '@scope/package'.") == (
        "Cannot find module '@scope/package'."
    )
    assert "private" not in diagnostic_message("Cannot find module 'a/../private'.")


@pytest.mark.parametrize(
    "source, private_fragments",
    [
        (
            "export const value: { private_field: number } = { private_field: 1 }; "
            "value.missing;",
            ("private_field",),
        ),
        (
            'export const value = "private-alpha" as "private-alpha" | "private-beta"; '
            "value.missing;",
            ("private-alpha", "private-beta"),
        ),
        (
            "class ghp_SyntheticType { present = 1; } "
            "export const value = new ghp_SyntheticType(); value.missing;",
            ("ghp_SyntheticType",),
        ),
        (
            "class ExampleType<T> { value!: T; } "
            "export const value = new ExampleType<number>(); value.missing;",
            ("ExampleType",),
        ),
    ],
)
def test_native_receiver_source_fragments_remain_private(
    context, source, private_fragments
):
    ctx = context([("private-control.ts", "typescript", source)], run)
    stage = analyze_ts_types(ctx)
    assert stage.status == "ok", stage.reason
    assert stage.version == "6.0.3"
    assert stage.metrics["source_error_count"] == 1
    message = stage.findings[0].message
    assert stage.findings[0].rule == "TS2339"
    assert "Property 'missing'" in message and "redacted" in message
    assert all(fragment not in message for fragment in private_fragments)
    assert ctx.files[0].path.read_text() == source


@pytest.mark.parametrize("kind", ["javascript", "eslint", "javac", "jdk"])
def test_default_consumers_ignore_native_messages(context, kind):
    ctx = context([("example.js", "javascript", "missing;\n")])
    rows = [
        {
            "path": str(ctx.files[0].path.resolve()),
            "line": 1,
            "column": 1,
            "rule": "example.rule",
            "severity": "medium",
            "message": None,
        }
    ]
    assert located_findings(rows, ctx.files, kind=kind)[0].message == (
        "Review example.rule diagnostic"
    )


@pytest.mark.parametrize("value", [None, 0, {}, ""])
def test_missing_native_message_is_rejected(value):
    with pytest.raises(ValueError, match="missing native diagnostic message"):
        diagnostic_message(value)


def test_plain_evidence_neutralizes_markup_without_markdown_escapes(monkeypatch):
    monkeypatch.setenv("FOLLOWUP_API_TOKEN", "synthetic-credential")
    message = diagnostic_message(
        "Property 'missing_field' does not exist on type 'Example_Type'. "
        "synthetic-credential /tmp/private/source.ts "
        "<script> [private](https://example.invalid) # *markup* | \x1b\u202e"
    )
    assert message.startswith(
        "Property 'missing_field' does not exist on type 'Example_Type'."
    )
    assert "[redacted]" in message and "[path]" in message
    assert all(
        fragment not in message
        for fragment in (
            "synthetic-credential",
            "/tmp/",
            "<script>",
            "[private]",
            "#",
            "*",
            "|",
            "\x1b",
            "\u202e",
            "\\",
        )
    )


@pytest.mark.parametrize(
    "message",
    [
        "Property 'missing' does not exist on type 'ExampleType",
        "Property 'missing' does not exist on type 'alpha'beta'delta'.",
        "Property 'missing' does not exist on type '`private`'.",
    ],
)
def test_unsafe_quoting_withholds_whole_message(message):
    assert diagnostic_message(message) == (
        "Native diagnostic text withheld because quoting was unsafe"
    )


def test_input_and_output_are_bounded():
    message = diagnostic_message("safe " * 1000 + "'unbalanced private")
    assert len(message) == 512 and "private" not in message
