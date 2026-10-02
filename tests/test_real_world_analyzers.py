"""Real output scale and adversarial controls for bounded analyzer adapters."""

import json
import shutil
import time
import xml.etree.ElementTree as ET
from dataclasses import replace

import pytest

from diff_gremlin.analyzers import batches
from diff_gremlin.analyzers.complexity import analyze_complexity
from diff_gremlin.analyzers.complexity_output import observations
from diff_gremlin.analyzers.python.execution import observe_python_calls
from diff_gremlin.analyzers.python.execution import source as python_source
from diff_gremlin.analyzers.python.ruff import analyze_ruff
from diff_gremlin.analyzers.shell import parser, schema
from diff_gremlin.analyzers.shell.stages import analyze_shell_syntax
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult
from diff_gremlin.process import run


def context(tmp_path, sources, runner=run):
    root = tmp_path / "source"
    root.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    files = []
    for relative, text in sources.items():
        path = root / relative
        path.write_text(text)
        language = "shell" if path.suffix == ".sh" else "python"
        files.append(SourceFile(path, relative, language, False, path.stat().st_size))
    return ScanContext(
        root, tuple(files), tuple(files), ("python",), "quick", 60, scratch, runner
    )


def test_native_ruff_large_output_batches_retain_every_diagnostic(tmp_path):
    if shutil.which("ruff") is None:
        pytest.skip("installed Ruff required")
    calls = []

    def runner(command, **kwargs):
        result = run(command, **kwargs)
        calls.append(result)
        return result

    source = "".join(f"value_{i} = undefined_{i}\n" for i in range(4000))
    ctx = context(tmp_path, {"a.py": source, "b.py": source, "c.py": source}, runner)
    stage = analyze_ruff(ctx)
    assert stage.status == "ok", stage.reason
    assert stage.analyzed_files == stage.eligible_files == 3
    assert stage.metrics["issue_count"] == len(stage.findings) == 12000
    assert any(result.status == "output_limit" for result in calls)
    assert all(finding.message == "Ruff F821 diagnostic" for finding in stage.findings)


def test_ruff_partial_batch_cannot_hide_later_malformed_output(tmp_path, monkeypatch):
    monkeypatch.setattr(batches, "MAX_BATCH_FILES", 1)

    def runner(command, **kwargs):
        if "--version" in command:
            return RunResult(tuple(command), 0, "ruff 0.16.8")
        if command[-1].endswith("a.py"):
            item = {
                "filename": "a.py",
                "location": {"row": 1, "column": 1},
                "code": "F821",
                "message": "private source",
            }
            return RunResult(tuple(command), 1, json.dumps([item]))
        return RunResult(tuple(command), 0, "{}")

    ctx = context(tmp_path, {"a.py": "missing\n", "b.py": "pass\n"}, runner)
    stage = analyze_ruff(ctx)
    assert stage.status == "limited" and stage.analyzed_files == 1
    assert stage.eligible_files == 2 and len(stage.findings) == 1
    assert "omitted 1" in stage.reason
    assert stage.findings[0].message == "Ruff F821 diagnostic"


def test_cumulative_batch_output_and_deadline_retain_prior_coverage(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(batches, "MAX_BATCH_FILES", 1)
    monkeypatch.setattr(batches, "MAX_TOTAL_OUTPUT_BYTES", 2)
    ctx = context(
        tmp_path,
        {"a.py": "pass\n", "b.py": "pass\n"},
        lambda command, **kwargs: RunResult(tuple(command), 0, "[]"),
    )
    stage = analyze_ruff(ctx)
    assert stage.status == "limited" and stage.analyzed_files == 1
    assert "cumulative output byte budget exhausted" in stage.reason
    assert analyze_ruff(replace(ctx, timeout=0)).status == "timeout"


def test_ruff_foreign_diagnostic_fails_the_owning_batch(tmp_path):
    item = {
        "filename": "outside.py",
        "location": {"row": 1, "column": 1},
        "code": "F821",
        "message": "private",
    }
    ctx = context(
        tmp_path,
        {"a.py": "pass\n"},
        lambda command, **kwargs: RunResult(tuple(command), 1, json.dumps([item])),
    )
    stage = analyze_ruff(ctx)
    assert stage.status == "failed" and stage.analyzed_files == 0
    assert not stage.metrics and not stage.findings


def test_native_lizard_negative_unused_ncss_is_valid(tmp_path):
    if shutil.which("lizard") is None:
        pytest.skip("installed Lizard required")
    source = 'def f(x):\n    call(f"""' + "    {x}\n" * 12 + '    """)\n'
    ctx = context(tmp_path, {"a.py": source})
    result = run(
        [
            "lizard",
            "--xml",
            "--no-gitignore",
            "--ignore_warnings",
            "-1",
            "--",
            str(ctx.files[0].path),
        ],
        cwd=ctx.scratch,
    )
    root = ET.fromstring(result.stdout)
    function = root.find("measure[@type='Function']/item")
    assert function is not None
    assert int(function.findall("value")[1].text) < 0
    stage = analyze_complexity(ctx)
    assert stage.status == "ok" and stage.metrics["max_cc"] == 1
    function.findall("value")[2].text = "-1"
    with pytest.raises(ValueError):
        observations(ctx, ctx.files, ET.tostring(root, encoding="unicode"))


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_file",
        "duplicate_function",
        "foreign_function",
        "wrong_count",
        "bad_integer",
    ],
)
def test_lizard_ncss_exception_preserves_schema_and_coverage_controls(
    tmp_path, mutation
):
    ctx = context(tmp_path, {"a.py": "def f():\n    return 1\n"})
    root = ET.fromstring(
        '<cppncss><measure type="Function"><item name="f(...) at a.py:1"><value>1</value><value>-11</value><value>1</value></item></measure><measure type="File"><item name="a.py"><value>1</value><value>-11</value><value>1</value><value>1</value></item></measure></cppncss>'
    )
    function_measure, file_measure = root.findall("measure")
    function = function_measure.find("item")
    file = file_measure.find("item")
    assert function is not None and file is not None
    if mutation == "missing_file":
        file_measure.remove(file)
    elif mutation == "duplicate_function":
        function_measure.append(ET.fromstring(ET.tostring(function)))
    elif mutation == "foreign_function":
        function.set("name", "f(...) at other.py:1")
    elif mutation == "wrong_count":
        file.findall("value")[3].text = "2"
    else:
        function.findall("value")[1].text = "not an integer"
    with pytest.raises(ValueError):
        observations(ctx, ctx.files, ET.tostring(root, encoding="unicode"))


def test_python_source_above_old_cap_keeps_real_call_and_bounds(tmp_path, monkeypatch):
    source = "# " + "x" * (1024 * 1024) + '\neval("private argument")\n'
    ctx = context(tmp_path, {"a.py": source})
    findings, count, reason = observe_python_calls(ctx.files)
    assert count == 1 and not reason and findings[0].rule == "python.eval"
    assert findings[0].line == 2 and "private argument" not in findings[0].message
    monkeypatch.setattr(python_source, "MAX_SOURCE_BYTES", 100)
    assert observe_python_calls(ctx.files)[1] == 0
    assert observe_python_calls(ctx.files, timeout=0)[1] == 0


def test_python_changed_linked_and_explosive_source_remains_incomplete(
    tmp_path, monkeypatch
):
    ctx = context(tmp_path, {"a.py": "value = 1\n"})
    monkeypatch.setattr(python_source, "MAX_AST_NODES", 1)
    assert observe_python_calls(ctx.files)[1] == 0
    monkeypatch.setattr(python_source, "MAX_AST_NODES", 500000)
    original = ctx.root / "saved"
    ctx.files[0].path.rename(original)
    ctx.files[0].path.symlink_to(original)
    assert observe_python_calls(ctx.files)[1] == 0


def test_native_shell_large_ast_and_total_output_keep_full_coverage(tmp_path):
    ctx = context(
        tmp_path, {f"{i}.sh": "#!/bin/sh\n" + "printf ok\n" * 6000 for i in range(3)}
    )
    binary, reason = parser.installed_parser(ctx)
    if not binary:
        pytest.skip(reason)
    result = run(
        [binary, "--to-json", "-ln=posix"],
        cwd=ctx.scratch,
        input_text=ctx.files[0].path.read_text(),
        data_output=True,
        output_limit=schema.MAX_JSON_BYTES,
    )
    assert len(result.stdout.encode()) > 8 * 1024 * 1024
    started = time.monotonic()
    stage = analyze_shell_syntax(ctx)
    assert stage.status == "ok", stage.reason
    assert stage.analyzed_files == stage.eligible_files == 3
    assert time.monotonic() - started < ctx.timeout
    compact = parser.parse_files(ctx, ctx.files)
    assert compact.analyzed == 3 and len(compact.calls) == 18000
    assert not hasattr(compact, "trees")


@pytest.mark.parametrize("kind", ["comment", "heredoc"])
def test_native_shell_derived_end_positions_require_exact_source_evidence(
    tmp_path, kind
):
    slash = chr(92)
    source = (
        "#!/bin/bash\n# continued comment " + slash + "\nprintf ok\n"
        if kind == "comment"
        else "#!/bin/bash\ncat <<EOF\nhello $value " + slash + "\nend\nEOF\n"
    )
    ctx = context(tmp_path, {"a.sh": source})
    binary, reason = parser.installed_parser(ctx)
    if not binary:
        pytest.skip(reason)
    result = run(
        [binary, "--to-json", "-ln=bash"],
        cwd=ctx.scratch,
        input_text=source,
        data_output=True,
    )
    assert schema.decode(result.stdout, source)["_kind"] == "File"
    tree = json.loads(result.stdout)
    if kind == "comment":
        node = tree["Stmts"][0]["Comments"][1]
        assert node["Text"].endswith(slash + "\n")
        node["Text"] = "forged comment" + slash + "\n"
    else:
        parts = tree["Stmts"][0]["Redirs"][0]["Hdoc"]["Parts"]
        node = next(part for part in parts if part.get("Value") == " ")
        assert node["ValueEnd"]["Col"] == node["ValuePos"]["Col"] + 1
        node["Value"] = "forged literal"
    with pytest.raises(ValueError):
        schema.decode(json.dumps(tree), source)
    tree = json.loads(result.stdout)
    if kind == "comment":
        node = tree["Stmts"][0]["Comments"][1]
    else:
        node = next(
            part
            for part in tree["Stmts"][0]["Redirs"][0]["Hdoc"]["Parts"]
            if part.get("Value") == " "
        )
    node["End"]["Line"] += 1
    with pytest.raises(ValueError):
        schema.decode(json.dumps(tree), source)
