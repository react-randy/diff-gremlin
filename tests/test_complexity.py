"""Controls for one Lizard observation per production function."""

import shutil

import pytest
from test_python_analyzers import FakeRunner, make_context, native_runner

from diff_gremlin.analyzers.complexity import analyze_complexity


def xml(
    function_rows="",
    file_rows='<item name="a.py"><value>1</value><value>3</value><value>0</value><value>0</value></item>',
):
    return f'<cppncss><measure type="Function">{function_rows}</measure><measure type="File">{file_rows}</measure></cppncss>'


def function(cc=12, path="a.py", name="compute", line=1):
    return f'<item name="{name}(...) at {path}:{line}"><value>1</value><value>3</value><value>{cc}</value></item>'


def file_row(functions=1, path="a.py"):
    return f'<item name="{path}"><value>1</value><value>3</value><value>12</value><value>{functions}</value></item>'


def test_one_cc_per_function_located_hotspot(tmp_path):
    runner = FakeRunner(xml(function(), file_row()))
    stage = analyze_complexity(make_context(tmp_path, runner))
    assert stage.status == "ok"
    assert stage.metrics == {
        "max_cc": 12,
        "average_cc": 12.0,
        "functions": 1,
        "hotspots": [{"file": "a.py", "function": "compute", "line": 1, "cc": 12}],
    }
    assert stage.findings[0].path == "a.py" and stage.findings[0].line == 1
    assert not any("radon" in command for command, _ in runner.calls)


def test_valid_zero_functions_distinct_from_missing_output(tmp_path):
    stage = analyze_complexity(
        make_context(tmp_path, FakeRunner(xml()), {"a.py": "value = 1\n"})
    )
    assert stage.status == "ok" and stage.metrics["functions"] == 0
    assert stage.metrics["max_cc"] == 0 and stage.analyzed_files == 1
    stage = analyze_complexity(make_context(tmp_path, FakeRunner("")))
    assert stage.status == "failed" and stage.metrics == {}


@pytest.mark.parametrize(
    "text",
    [
        "",
        "not xml",
        "<wrong/>",
        "<cppncss/>",
        xml(function(), ""),
        xml(function(path="../outside.py"), file_row()),
        xml(function(cc=0), file_row()),
        xml(function(line=0), file_row()),
        xml(function() + function(), file_row(2)),
        xml(function(), file_row(2)),
        xml("", file_row(1)),
        "<!DOCTYPE cppncss><cppncss/>",
    ],
)
def test_invalid_or_partial_output_never_clean(tmp_path, text):
    stage = analyze_complexity(make_context(tmp_path, FakeRunner(text)))
    assert (
        stage.status == "failed" and stage.metrics == {} and stage.analyzed_files == 0
    )


@pytest.mark.parametrize(
    "status,code",
    [
        ("missing", None),
        ("timeout", None),
        ("failed", None),
        ("output_limit", 0),
        ("ok", 2),
        ("ok", 1),
    ],
)
def test_failed_lizard_execution(tmp_path, status, code):
    stage = analyze_complexity(make_context(tmp_path, FakeRunner(xml(), code, status)))
    assert stage.status in ("missing", "timeout", "failed") and not stage.metrics


def test_only_supported_production_files_eligible(tmp_path):
    runner = FakeRunner(xml())
    ctx = make_context(
        tmp_path, runner, {"a.py": "value = 1\n", "unknown.txt": "uncovered"}
    )
    stage = analyze_complexity(ctx)
    assert (
        stage.status == "ok" and stage.eligible_files == 1 and stage.analyzed_files == 1
    )


@pytest.mark.parametrize(
    "filename,source",
    [
        ("a.py", "def choose(x):\n    if x:\n        return 1\n    return 0\n"),
        (
            "Example.java",
            "class Example { int choose(boolean x) { if (x) return 1; return 0; } }",
        ),
        ("a.rs", "fn choose(x: bool) -> i32 { if x { 1 } else { 0 } }"),
        ("a.c", "int choose(int x) { if (x) return 1; return 0; }"),
        (
            "a.go",
            "package main\nfunc choose(x bool) int { if x { return 1 }; return 0 }",
        ),
        ("a.rb", "def choose(x)\n if x\n  return 1\n end\n return 0\nend"),
        ("a.swift", "func choose(_ x: Bool) -> Int { if x { return 1 }; return 0 }"),
        ("a.lua", "function choose(x)\n if x then return 1 end\n return 0\nend"),
        ("a.m", "int choose(int x) { if (x) return 1; return 0; }"),
    ],
)
def test_native_supported_language_function_once(tmp_path, filename, source):
    if shutil.which("lizard") is None:
        pytest.skip("optional native pilot requires installed lizard")
    stage = analyze_complexity(
        make_context(tmp_path, native_runner, {filename: source})
    )
    assert stage.status == "ok", stage.reason
    assert (
        stage.metrics["functions"] == 1
        and stage.metrics["average_cc"] == 2
        and stage.metrics["max_cc"] == 2
    )


def test_native_file_with_no_functions_and_path_spaces(tmp_path):
    if shutil.which("lizard") is None:
        pytest.skip("optional native pilot requires installed lizard")
    stage = analyze_complexity(
        make_context(
            tmp_path, native_runner, {"folder with spaces/a.py": "value = 1\n"}
        )
    )
    assert (
        stage.status == "ok"
        and stage.metrics["functions"] == 0
        and stage.analyzed_files == 1
    )


def test_native_scala_parser_gap_is_visible(tmp_path):
    if shutil.which("lizard") is None:
        pytest.skip("optional native pilot requires installed lizard")
    source = "object Example { def choose(x: Boolean): Int = { if (x) 1 else 0 } }"
    stage = analyze_complexity(
        make_context(tmp_path, native_runner, {"a.scala": source})
    )
    assert stage.status == "limited" and "Scala" in stage.reason
    assert "max_cc" not in stage.metrics and "average_cc" not in stage.metrics


def test_python_declaration_cannot_be_hidden_as_known_zero(tmp_path):
    stage = analyze_complexity(make_context(tmp_path, FakeRunner(xml())))
    assert stage.status == "failed" and not stage.metrics


@pytest.mark.parametrize("body", ["...", '"""Interface only."""; ...'])
def test_native_protocol_declarations_are_accounted_for_without_hiding_real_bodies(
    tmp_path, body
):
    source = (
        "from typing import Protocol\n"
        f"class Example(Protocol):\n    def call(self) -> int: {body}\n"
        "def choose(value):\n    if value:\n        return 1\n    return 0\n"
    )
    stage = analyze_complexity(make_context(tmp_path, native_runner, {"a.py": source}))
    assert stage.status == "ok", stage.reason
    assert stage.metrics["functions"] == 2
    assert stage.metrics["max_cc"] == 2
    assert stage.metrics["average_cc"] == 1.5
    declarations = stage.metrics.get("declarations", [])
    if declarations:
        assert declarations == [
            {
                "file": "a.py",
                "function": "Example.call",
                "line": 3,
                "cc": 1,
                "origin": "python-ast-ellipsis-declaration",
            }
        ]


def test_stub_does_not_explain_missing_executable_function_evidence(tmp_path):
    source = "def interface(): ...\ndef choose(value):\n    if value:\n        return 1\n    return 0\n"
    stage = analyze_complexity(
        make_context(tmp_path, FakeRunner(xml()), {"a.py": source})
    )
    assert stage.status == "failed" and stage.metrics == {}
