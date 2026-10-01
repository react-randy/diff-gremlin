"""Native positives must survive, and corrupted coordinates must lose coverage."""

import json
import re
from dataclasses import replace

import pytest

from diff_gremlin.analyzers.execution import analyze_execution
from diff_gremlin.analyzers.java.structure import analyze_java_structure
from diff_gremlin.analyzers.java.types import analyze_java_types
from diff_gremlin.analyzers.javascript.lint import analyze_js_lint
from diff_gremlin.analyzers.javascript.types import analyze_ts_types
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.process import run

CASES = [
    (
        analyze_js_lint,
        "lint.cjs",
        "javascript",
        "Sample.js",
        "console.log(missingName);",
    ),
    (
        analyze_ts_types,
        "types.cjs",
        "typescript",
        "Sample.ts",
        "export const n: number = 'bad';",
    ),
    (
        analyze_execution,
        "execution.cjs",
        "javascript",
        "Sample.js",
        "eval('synthetic');",
    ),
    (
        analyze_java_structure,
        "StructureProbe",
        "java",
        "Sample.java",
        "class Sample { void f() { System.exit(0); } }",
    ),
    (
        analyze_java_types,
        "-XDrawDiagnostics",
        "java",
        "Sample.java",
        'class Sample { int n = "bad"; }',
    ),
]


@pytest.fixture
def context(tmp_path):
    source, scratch = tmp_path / "source", tmp_path / "scratch"
    source.mkdir()
    scratch.mkdir()

    def make(language, name, text, runner=run):
        path = source / name
        path.write_bytes(text.encode("utf-8"))
        file = SourceFile(path, name, language, False, path.stat().st_size)
        return ScanContext(
            source, (file,), (file,), (language,), "full", 30, scratch, runner
        )

    return make


def _native_result(command, kwargs, marker):
    result = run(command, **kwargs)
    if not any(str(arg).endswith(marker) for arg in command):
        return result, None
    assert result.status == "ok", result
    if marker == "-XDrawDiagnostics":
        assert re.search(r"Sample.java:\d+:\d+: compiler.err.", result.stderr)
        return result, None
    data = json.loads(result.stdout)
    assert data["findings"], "Real native positive required before evidence corruption"
    return result, data


@pytest.mark.parametrize("analyzer,marker,language,name,text", CASES)
@pytest.mark.parametrize(
    "field,value", [("line", 999999), ("column", 999999), ("line", 0), ("column", 0)]
)
def test_native_impossible_coordinate_loses_coverage(
    context, analyzer, marker, language, name, text, field, value
):
    def corrupt(command, **kwargs):
        result, data = _native_result(command, kwargs, marker)
        if not any(str(arg).endswith(marker) for arg in command):
            return result
        if marker == "-XDrawDiagnostics":
            index = 1 if field == "line" else 2
            parts = result.stderr.split(":", 3)
            parts[index] = str(value)
            return replace(result, stderr=":".join(parts))
        data["findings"][0][field] = value
        return replace(result, stdout=json.dumps(data))

    result = analyzer(context(language, name, text, corrupt))
    assert result.status in {"failed", "limited"}, result.reason
    assert result.analyzed_files == 0 and result.eligible_files == 1
    assert result.findings == []


@pytest.mark.parametrize("analyzer,marker,language,name,text", CASES)
@pytest.mark.parametrize("failure", ["unreadable", "oversized"])
def test_native_location_requires_bounded_readable_source(
    context, analyzer, marker, language, name, text, failure
):
    ctx = None

    def corrupt_source(command, **kwargs):
        result, _ = _native_result(command, kwargs, marker)
        if any(str(arg).endswith(marker) for arg in command):
            path = ctx.files[0].path
            if failure == "unreadable":
                path.unlink()
            else:
                path.write_bytes(b" " * (4 * 1024 * 1024 + 1))
        return result

    ctx = context(language, name, text, corrupt_source)
    result = analyzer(ctx)
    assert result.status in {"failed", "limited"}, result.reason
    assert result.analyzed_files == 0 and result.findings == []


@pytest.mark.parametrize("separator", ["\n", "\r", "\r\n", "\u2028", "\u2029"])
@pytest.mark.parametrize(
    "analyzer,language,name,tail,rule",
    [
        (
            analyze_js_lint,
            "javascript",
            "Sample.js",
            "console.log(missingName);",
            "no-undef",
        ),
        (
            analyze_ts_types,
            "typescript",
            "Sample.ts",
            "export const n: number = 'bad';",
            "TS2322",
        ),
        (
            analyze_execution,
            "javascript",
            "Sample.js",
            "eval('synthetic');",
            "javascript.eval",
        ),
    ],
)
def test_native_js_utf16_and_line_breaks_remain_located(
    context, separator, analyzer, language, name, tail, rule
):
    prefix = 'const text = "🦋"; console.log(text);'
    result = analyzer(context(language, name, prefix + separator + '\t"🦋"; ' + tail))
    assert result.status == "ok", result.reason
    assert result.analyzed_files == result.eligible_files == 1
    finding = next(f for f in result.findings if f.rule == rule)
    assert finding.line == 2
    assert finding.column >= 8


@pytest.mark.parametrize("separator", ["", "\n", "\r", "\r\n", "\u2028", "\u2029"])
@pytest.mark.parametrize(
    "analyzer,name,language",
    [
        (analyze_js_lint, "Sample.js", "javascript"),
        (analyze_ts_types, "Sample.ts", "typescript"),
    ],
)
def test_native_javascript_eof_syntax_remains_located(
    context, separator, analyzer, name, language
):
    result = analyzer(context(language, name, "function f(" + separator))
    assert result.status == "ok", result.reason
    assert result.analyzed_files == 1 and result.findings
    assert any(f.line == (2 if separator else 1) for f in result.findings)


@pytest.mark.parametrize("separator", ["", "\n", "\r", "\r\n"])
@pytest.mark.parametrize("analyzer", [analyze_java_types, analyze_java_structure])
def test_native_java_eof_syntax_remains_located(context, separator, analyzer):
    result = analyzer(context("java", "Sample.java", "class Sample {" + separator))
    assert result.status == "ok", result.reason
    assert result.analyzed_files == 1 and result.findings


@pytest.mark.parametrize("separator", ["\n", "\r", "\r\n"])
@pytest.mark.parametrize(
    "analyzer,text,rule,column",
    [
        (analyze_java_structure, "System.exit(0);", "java.system-exit", 17),
        (analyze_java_types, 'int n = "bad";', "compiler.err.prob.found.req", 25),
    ],
)
def test_native_java_tabs_and_utf16_remain_located(
    context, separator, analyzer, text, rule, column
):
    header = (
        "class Sample { void f() {"
        if analyzer == analyze_java_structure
        else "class Sample {"
    )
    tail = " } }" if analyzer == analyze_java_structure else " }"
    result = analyzer(
        context("java", "Sample.java", header + separator + "\t\t" + text + tail)
    )
    assert result.status == "ok", result.reason
    finding = next(f for f in result.findings if f.rule == rule)
    assert (finding.line, finding.column) == (2, column)


@pytest.mark.parametrize("field", ["line", "column"])
def test_native_boolean_coordinate_is_not_an_integer(context, field):
    def corrupt(command, **kwargs):
        result, data = _native_result(command, kwargs, "lint.cjs")
        if data is not None:
            data["findings"][0][field] = True
            return replace(result, stdout=json.dumps(data))
        return result

    result = analyze_js_lint(
        context("javascript", "Sample.js", "console.log(missingName);", corrupt)
    )
    assert result.status == "failed" and result.analyzed_files == 0


@pytest.mark.parametrize("column", [2, 10])
def test_native_jdk_tab_gap_cannot_be_a_source_position(context, column):
    def corrupt(command, **kwargs):
        result, data = _native_result(command, kwargs, "StructureProbe")
        if data is not None:
            assert data["findings"][0]["column"] == 17
            data["findings"][0]["column"] = column
            return replace(result, stdout=json.dumps(data))
        return result

    result = analyze_java_structure(
        context(
            "java",
            "Sample.java",
            "class Sample { void f() {\n\t\tSystem.exit(0); } }",
            corrupt,
        )
    )
    assert result.status == "failed" and result.analyzed_files == 0


def test_native_java_counts_supplementary_character_as_two_units(context):
    prefix = 'class Sample { void f() { String note = "🦋"; '
    result = analyze_java_structure(
        context("java", "Sample.java", prefix + "System.exit(0); } }")
    )
    assert result.status == "ok", result.reason
    finding = next(f for f in result.findings if f.rule == "java.system-exit")
    assert finding.column == len(prefix.encode("utf-16-le")) // 2 + 1


@pytest.mark.parametrize(
    "analyzer,language,name",
    [
        (analyze_js_lint, "javascript", "Sample.js"),
        (analyze_ts_types, "typescript", "Sample.ts"),
    ],
)
def test_native_bom_is_removed_from_lint_and_compiler_coordinates(
    context, analyzer, language, name
):
    result = analyzer(context(language, name, "\ufefffunction f("))
    assert result.status == "ok", result.reason
    expected = 11 if analyzer == analyze_js_lint else 12
    assert any(f.column == expected for f in result.findings)


def test_native_sources_share_one_coordinate_read_budget(context, monkeypatch):
    text = "console.log(missingName);"
    ctx = context("javascript", "First.js", text)
    second = ctx.root / "Second.js"
    second.write_text(text, encoding="utf-8")
    file = SourceFile(second, second.name, "javascript", False, second.stat().st_size)
    ctx = replace(ctx, files=(*ctx.files, file), production_files=(*ctx.files, file))
    positive = analyze_js_lint(ctx)
    assert positive.status == "ok" and len(positive.findings) == 2
    monkeypatch.setattr(
        "diff_gremlin.analyzers.javascript.coordinates._MAX_SOURCE_BYTES",
        len(text.encode()) + 1,
    )
    result = analyze_js_lint(ctx)
    assert result.status == "failed" and result.analyzed_files == 0
    assert "coordinate read budget" in result.reason


@pytest.mark.parametrize(
    "encoding,bom", [("utf-16-le", b"\xff\xfe"), ("utf-16-be", b"\xfe\xff")]
)
def test_native_compiler_bom_encoding_keeps_its_source_coordinates(
    context, encoding, bom
):
    ctx = context("typescript", "Sample.ts", "function f(")
    path = ctx.files[0].path
    path.write_bytes(bom + "function f(".encode(encoding))
    file = replace(ctx.files[0], size_bytes=path.stat().st_size)
    result = analyze_ts_types(replace(ctx, files=(file,), production_files=(file,)))
    assert result.status == "ok", result.reason
    assert any(f.column == 12 for f in result.findings)
