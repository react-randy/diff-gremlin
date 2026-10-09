"""Native ESLint and Lizard controls for stable function comparison identity."""

import shutil
from pathlib import Path

import pytest

from diff_gremlin.analyzers.complexity import analyze_complexity, analyze_php_complexity
from diff_gremlin.analyzers.javascript.complexity import analyze_js_complexity
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.process import run
from diff_gremlin.reporting.delta import stage_delta


def context(directory: Path, filename: str, source: str, language: str) -> ScanContext:
    root, scratch = directory / "source", directory / "scratch"
    root.mkdir(parents=True)
    scratch.mkdir()
    file = root / filename
    file.write_text(source)
    row = SourceFile(file, filename, language, False, file.stat().st_size)
    return ScanContext(root, (row,), (row,), (language,), "full", 30, scratch, run)


def js_function(name="choose", cc=12):
    return (
        f"function {name}(value) {{\n"
        + "".join(
            f"if (value === {index}) return {index};\n" for index in range(cc - 1)
        )
        + "return -1;\n}\n"
    )


def js_stage(directory, source):
    if not shutil.which("eslint") or not shutil.which("node"):
        pytest.skip("native identity controls need trusted ESLint and Node")
    result = analyze_js_complexity(
        context(directory, "example.js", source, "javascript")
    )
    assert result.status == "ok", result.reason
    return result


def test_native_moved_named_hotspot_has_same_identity_and_no_churn(tmp_path):
    base = js_stage(tmp_path / "base", js_function())
    head = js_stage(tmp_path / "head", "\n\n" + js_function())
    delta = stage_delta(base, head)
    assert base.findings[0].symbol == "choose"
    assert base.findings[0].fingerprint == head.findings[0].fingerprint
    assert base.findings[0].line + 2 == head.findings[0].line
    assert (
        delta["added_findings"]
        == delta["resolved_findings"]
        == delta["changed_findings"]
        == []
    )


def test_native_grown_function_retains_identity_and_explicit_value(tmp_path):
    base = js_stage(
        tmp_path / "base", js_function(cc=52) + js_function("inherited", 113)
    )
    head = js_stage(
        tmp_path / "head", js_function(cc=61) + js_function("inherited", 113)
    )
    delta = stage_delta(base, head)
    assert base.metrics["max_cc"] == head.metrics["max_cc"] == 113
    assert delta["added_findings"] == delta["resolved_findings"] == []
    assert delta["changed_findings"][0]["measurement"] == {
        "metric": "cyclomatic_complexity",
        "base": 52,
        "head": 61,
        "delta": 9,
    }


def test_native_duplicate_short_names_are_qualified_by_lexical_owner(tmp_path):
    source = (
        "class First { " + js_function() + "}\nclass Second { " + js_function() + "}\n"
    )
    # Method syntax omits the function keyword.
    source = source.replace("function choose", "choose")
    result = js_stage(tmp_path, source)
    assert {finding.symbol for finding in result.findings} == {
        "First.method:choose",
        "Second.method:choose",
    }
    assert len({finding.fingerprint for finding in result.findings}) == 2


def test_native_nested_named_functions_retain_function_owner(tmp_path):
    source = "function outer() {\n" + js_function() + "return choose;\n}\n"
    result = js_stage(tmp_path, source)
    assert result.findings[0].symbol == "outer.choose"


def test_native_private_and_public_members_keep_distinct_identity(tmp_path):
    private = js_function().replace("function choose", "#choose")
    public = js_function().replace("function choose", "choose")
    result = js_stage(tmp_path, "class Example {\n" + private + public + "}\n")
    assert {finding.symbol for finding in result.findings} == {
        "Example.method:#choose",
        "Example.method:choose",
    }
    assert len({finding.fingerprint for finding in result.findings}) == 2


def test_native_anonymous_body_matches_moves_but_changed_body_is_unpaired(tmp_path):
    body = js_function().replace("function choose", "function")
    base = js_stage(tmp_path / "base", "const callbacks = [" + body + "];\n")
    moved = js_stage(tmp_path / "moved", "\n\nconst callbacks = [" + body + "];\n")
    assert base.findings[0].identity_kind == "body"
    assert base.findings[0].fingerprint == moved.findings[0].fingerprint
    assert not stage_delta(base, moved)["added_findings"]
    changed = js_stage(
        tmp_path / "changed",
        "const callbacks = [" + body.replace("return -1", "return -2") + "];\n",
    )
    delta = stage_delta(base, changed)
    assert len(delta["added_findings"]) == len(delta["resolved_findings"]) == 1
    assert not delta["changed_findings"] and delta["uncertain_identities"]


def test_native_same_line_anonymous_duplicates_are_not_silently_changed(tmp_path):
    body = js_function(cc=12).replace("function choose", "function").replace("\n", " ")
    base = js_stage(tmp_path / "base", f"const callbacks = [{body}, {body}];")
    head = js_stage(tmp_path / "head", "\n" + f"const callbacks = [{body}, {body}];")
    assert len(base.findings) == 2
    assert base.findings[0].fingerprint == base.findings[1].fingerprint
    assert stage_delta(base, head)["unchanged_findings"] == 2


@pytest.mark.parametrize(
    "language,filename", [("python", "example.py"), ("php", "example.php")]
)
def test_native_lizard_qualified_functions_move_without_churn(
    tmp_path, language, filename
):
    if not shutil.which("lizard"):
        pytest.skip("native identity controls need installed Lizard")
    if language == "python":
        method = (
            "    def choose(self, value):\n"
            + "".join(
                f"        if value == {index}:\n            return {index}\n"
                for index in range(11)
            )
            + "        return -1\n"
        )
        source = "class First:\n" + method + "class Second:\n" + method
        analyze = analyze_complexity
    else:
        method = (
            "function choose($value) {\n"
            + "".join(
                f"if ($value === {index}) return {index};\n" for index in range(11)
            )
            + "return -1;\n}\n"
        )
        source = (
            "<?php\nclass First {\n" + method + "}\nclass Second {\n" + method + "}\n"
        )
        analyze = analyze_php_complexity
    before = analyze(context(tmp_path / "base", filename, source, language))
    prefix = "\n\n" if language == "python" else "<?php\n\n\n"
    moved = prefix + (
        source if language == "python" else source.removeprefix("<?php\n")
    )
    after = analyze(context(tmp_path / "head", filename, moved, language))
    assert before.status == after.status == "ok", (before.reason, after.reason)
    assert (
        len(before.findings) == 2
        and len({finding.symbol for finding in before.findings}) == 2
    )
    delta = stage_delta(before, after)
    assert not delta["added_findings"] and not delta["resolved_findings"]
    assert delta["unchanged_findings"] == 2


def test_native_lizard_growth_keeps_named_identity(tmp_path):
    if not shutil.which("lizard"):
        pytest.skip("native identity controls need installed Lizard")

    def source(branches):
        return (
            "<?php\nclass Example { function choose($value) {\n"
            + "".join(
                f"if ($value === {index}) return {index};\n"
                for index in range(branches)
            )
            + "return -1;\n} }\n"
        )

    before = analyze_php_complexity(
        context(tmp_path / "base", "example.php", source(11), "php")
    )
    after = analyze_php_complexity(
        context(tmp_path / "head", "example.php", source(14), "php")
    )
    assert before.status == after.status == "ok"
    change = stage_delta(before, after)["changed_findings"][0]
    assert change["measurement"] == {
        "metric": "cyclomatic_complexity",
        "base": 12,
        "head": 15,
        "delta": 3,
    }
