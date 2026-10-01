"""Independent native controls for correctness, value identity and located evidence."""

import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode

import pytest

from diff_gremlin.analyzers.execution import analyze_execution
from diff_gremlin.analyzers.javascript.duplication import analyze_js_duplication
from diff_gremlin.analyzers.javascript.lint import analyze_js_lint
from diff_gremlin.analyzers.secrets import analyze_secrets
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.process import run

LONG = (
    "export function calculate(input: number): number {\n"
    + "".join(f" const value{i} = input * {i + 2};\n" for i in range(25))
    + " return value0;\n}\n"
)


@pytest.fixture
def context(tmp_path):
    root, scratch = tmp_path / "source", tmp_path / "scratch"
    root.mkdir()
    scratch.mkdir()

    def make(sources, runner=run):
        files = []
        for name, language, text in sources:
            path = root / name
            path.write_text(text, encoding="utf-8")
            files.append(SourceFile(path, name, language, False, path.stat().st_size))
        languages = tuple(sorted({file.language for file in files}))
        return ScanContext(
            root, tuple(files), tuple(files), languages, "full", 30, scratch, runner
        )

    return make


@pytest.mark.parametrize("extension", ["js", "jsx", "mjs", "cjs"])
def test_native_javascript_reports_undefined_identifiers(context, extension):
    result = analyze_js_lint(
        context([(f"missing.{extension}", "javascript", "console.log(missingName);")])
    )
    assert result.status == "ok", result.reason
    assert result.analyzed_files == result.eligible_files == 1
    assert [(f.rule, f.line) for f in result.findings] == [("no-undef", 1)]


@pytest.mark.parametrize("extension", ["js", "jsx", "mjs", "cjs"])
def test_native_javascript_retains_defined_and_runtime_globals(context, extension):
    result = analyze_js_lint(
        context(
            [
                (
                    f"defined.{extension}",
                    "javascript",
                    "const value = 1; console.log(value, process.version, "
                    "window.location, document.title, Buffer, module, require);",
                )
            ]
        )
    )
    assert result.status == "ok", result.reason
    assert result.findings == []


def test_native_typescript_retains_its_undefined_name_override(context):
    result = analyze_js_lint(
        context([("typed.ts", "typescript", "export const value: ExternalType = 1;")])
    )
    assert result.status == "ok", result.reason
    assert "no-undef" not in {finding.rule for finding in result.findings}


@pytest.mark.parametrize(
    "source,expected_lines",
    [
        (
            "let execute = eval;\n"
            "class Unused { field = (execute = value => value); }\n"
            'execute("synthetic");',
            [3],
        ),
        (
            "let execute = value => value;\n"
            "class Unused { field = (execute = eval); }\n"
            'execute("ordinary");',
            [],
        ),
        (
            "let execute = eval;\n"
            'class Unused { field = execute("synthetic"); }\n'
            'execute("synthetic");',
            [2, 3],
        ),
        (
            "let execute = value => value;\n"
            'class Unused { field = (execute = eval, execute("synthetic")); }\n'
            'execute("ordinary");',
            [2],
        ),
        (
            "let execute = eval;\n"
            "class Used { static field = (execute = value => value); }\n"
            'execute("ordinary");',
            [],
        ),
        (
            "let execute = value => value;\n"
            "class Used { static field = (execute = eval); }\n"
            'execute("synthetic");',
            [3],
        ),
        (
            "let execute = eval;\n"
            'class Used { [execute = value => value, "field"] = 1; }\n'
            'execute("ordinary");',
            [],
        ),
        (
            "let execute = value => value;\n"
            'class Used { [execute = eval, "field"] = 1; }\n'
            'execute("synthetic");',
            [3],
        ),
    ],
)
def test_native_class_initialization_obeys_deferred_owner_boundary(
    context, source, expected_lines
):
    result = analyze_execution(context([("fields.ts", "typescript", source)]))
    assert result.status == "ok", result.reason
    assert [(f.rule, f.line) for f in result.findings] == [
        ("javascript.eval", line) for line in expected_lines
    ]


@pytest.mark.parametrize("wrapper", ["eval satisfies Function", "<Function>eval"])
def test_native_transparent_typescript_wrappers_preserve_sink(context, wrapper):
    result = analyze_execution(
        context(
            [
                (
                    "wrapper.ts",
                    "typescript",
                    f'const execute = {wrapper};\nexecute("synthetic");',
                )
            ]
        )
    )
    assert result.status == "ok", result.reason
    assert [(f.rule, f.line) for f in result.findings] == [("javascript.eval", 2)]


@pytest.mark.parametrize("wrapper", ["eval satisfies Function", "<Function>eval"])
def test_native_transparent_typescript_wrappers_respect_shadow(context, wrapper):
    result = analyze_execution(
        context(
            [
                (
                    "shadow.ts",
                    "typescript",
                    "const eval = value => value;\n"
                    f'const execute = {wrapper};\nexecute("ordinary");',
                )
            ]
        )
    )
    assert result.status == "ok", result.reason
    assert result.findings == []


def bedrock_token():
    fields = {
        "Action": "CallWithBearerToken",
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": "AKIA0000000000000000/20261001/us-west-2/bedrock/aws4_request",
        "X-Amz-Date": "20261001T000000Z",
        "X-Amz-Expires": "3600",
        "X-Amz-SignedHeaders": "host",
        "X-Amz-Signature": hashlib.sha256(
            b"independent-nonfunctional-control"
        ).hexdigest(),
    }
    payload = "bedrock.amazonaws.com/?" + urlencode(fields) + "&Version=1"
    return "bedrock-api-key-" + base64.b64encode(payload.encode()).decode()


@pytest.mark.parametrize("delimiter", [")", "]", "}", ",", ":", ";", "\n", '"', ""])
def test_native_complete_bedrock_token_accepts_non_base64_boundary(context, delimiter):
    token = bedrock_token()
    result = analyze_secrets(
        context([("credential.txt", "text", "credential=(" + token + delimiter)])
    )
    assert result.status == "ok", result.reason
    assert "secret.aws-amazon-bedrock-api-key-short-lived" in {
        finding.rule for finding in result.findings
    }
    assert token not in repr(result)
    assert all(finding.line == 1 for finding in result.findings)


@pytest.mark.parametrize("continuation", ["A", "+", "/", "="])
def test_native_bedrock_token_does_not_accept_a_base64_prefix(context, continuation):
    result = analyze_secrets(
        context([("not-complete.txt", "text", bedrock_token() + continuation)])
    )
    assert result.status == "ok", result.reason
    assert "secret.aws-amazon-bedrock-api-key-short-lived" not in {
        finding.rule for finding in result.findings
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("start", 999999),
        ("start", 0),
        ("start", True),
        ("end", 999999),
        ("end", 0),
        ("end", True),
        ("start", 27),
        ("startLoc", {"line": 999999, "column": 1, "position": 0}),
        ("startLoc", {"line": True, "column": 1, "position": 0}),
        ("startLoc", {"line": 1, "column": 0, "position": 0}),
        ("startLoc", {"line": 1, "column": 999999, "position": 0}),
        ("startLoc", {"line": 1, "column": 1, "position": True}),
        ("endLoc", {"line": 999999, "column": 1, "position": 100}),
        ("endLoc", {"line": 28, "column": 999999, "position": 373}),
    ],
)
def test_native_clone_location_corruption_fails_evidence(context, field, value):
    def corrupt(command, **kwargs):
        result = run(command, **kwargs)
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        data = json.loads(report.read_text())
        assert data["duplicates"], "Native clone positive required before corruption"
        data["duplicates"][0]["firstFile"][field] = value
        report.write_text(json.dumps(data))
        return result

    result = analyze_js_duplication(
        context(
            [("first.ts", "typescript", LONG), ("second.ts", "typescript", LONG)],
            corrupt,
        )
    )
    assert result.status == "failed", result.reason
    assert result.analyzed_files == 0
    assert result.findings == [] and result.metrics == {}


@pytest.mark.parametrize("field,value", [("lines", 0), ("lines", 999999), ("lines", 1)])
def test_native_clone_extent_corruption_fails_evidence(context, field, value):
    def corrupt(command, **kwargs):
        result = run(command, **kwargs)
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        data = json.loads(report.read_text())
        assert data["duplicates"], "Native clone positive required before corruption"
        data["duplicates"][0][field] = value
        report.write_text(json.dumps(data))
        return result

    result = analyze_js_duplication(
        context(
            [("first.ts", "typescript", LONG), ("second.ts", "typescript", LONG)],
            corrupt,
        )
    )
    assert result.status == "failed", result.reason
    assert result.analyzed_files == 0
    assert result.findings == [] and result.metrics == {}


def test_native_genuine_clone_ranges_remain_located(context):
    result = analyze_js_duplication(
        context([("first.ts", "typescript", LONG), ("second.ts", "typescript", LONG)])
    )
    assert result.status == "ok", result.reason
    assert result.analyzed_files == result.eligible_files == 2
    assert result.metrics["clone_groups"] == 1
    assert {finding.path for finding in result.findings} == {"first.ts", "second.ts"}
    assert all(
        1 <= finding.line <= len(LONG.splitlines()) for finding in result.findings
    )


@pytest.mark.parametrize("variant", ["blank-lines", "comments", "crlf", "unicode"])
def test_native_clone_source_coordinates_preserve_valid_variants(context, variant):
    originals = {
        "blank-lines": LONG,
        "comments": LONG.replace("\n", "\n// explanatory comment\n"),
        "crlf": LONG.replace("\n", "\r\n"),
        "unicode": LONG.replace("return value0", 'return value0 + "🦋".length'),
    }
    alternatives = {
        "blank-lines": LONG.replace("\n", "\n\n"),
    }
    original = originals[variant]
    result = analyze_js_duplication(
        context(
            [
                ("first.ts", "typescript", original),
                ("second.ts", "typescript", alternatives.get(variant, original)),
            ]
        )
    )
    assert result.status == "ok", result.reason
    assert result.analyzed_files == result.eligible_files == 2
    assert result.metrics["clone_groups"] >= 1
    assert {finding.path for finding in result.findings} == {"first.ts", "second.ts"}


def test_native_reversed_clone_range_fails_evidence(context):
    def corrupt(command, **kwargs):
        result = run(command, **kwargs)
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        data = json.loads(report.read_text())
        location = data["duplicates"][0]["firstFile"]
        location["start"], location["end"] = location["end"], location["start"]
        location["startLoc"], location["endLoc"] = (
            location["endLoc"],
            location["startLoc"],
        )
        report.write_text(json.dumps(data))
        return result

    result = analyze_js_duplication(
        context(
            [("first.ts", "typescript", LONG), ("second.ts", "typescript", LONG)],
            corrupt,
        )
    )
    assert result.status == "failed", result.reason
    assert result.analyzed_files == 0
    assert result.findings == [] and result.metrics == {}


def test_native_oversized_clone_report_fails_bounded_read(context):
    def corrupt(command, **kwargs):
        result = run(command, **kwargs)
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        data = json.loads(report.read_text())
        data["padding"] = " " * (4 * 1024 * 1024)
        report.write_text(json.dumps(data))
        return result

    result = analyze_js_duplication(
        context(
            [("first.ts", "typescript", LONG), ("second.ts", "typescript", LONG)],
            corrupt,
        )
    )
    assert result.status == "failed", result.reason
    assert result.analyzed_files == 0
    assert result.findings == [] and result.metrics == {}
