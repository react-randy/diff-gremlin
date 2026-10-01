"""Controls for Python tool evidence validity and isolated native behavior."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from diff_gremlin.analyzers.python.maintainability import analyze_maintainability
from diff_gremlin.analyzers.python.pyscn import analyze_pyscn
from diff_gremlin.analyzers.python.ruff import analyze_ruff
from diff_gremlin.analyzers.python.types import analyze_python_types
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult


class FakeRunner:
    def __init__(self, output, code=0, status="ok"):
        self.output = output
        self.code = code
        self.status = status
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), kwargs))
        if "--version" in command:
            return RunResult(tuple(command), 0, "tool 1.2.3")
        return RunResult(tuple(command), self.code, self.output, status=self.status)


def native_runner(command, **kwargs):
    """Only trusted installed tools inspect fixture text; no target code runs."""
    env = {
        "PATH": os.environ["PATH"],
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        result = subprocess.run(
            command,
            cwd=kwargs["cwd"],
            timeout=kwargs["timeout"],
            input=kwargs.get("input_text"),
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
    except FileNotFoundError:
        return RunResult(tuple(command), None, status="missing")
    except subprocess.TimeoutExpired:
        return RunResult(tuple(command), None, status="timeout")
    if len(result.stdout.encode()) > kwargs["output_limit"]:
        return RunResult(tuple(command), result.returncode, status="output_limit")
    return RunResult(tuple(command), result.returncode, result.stdout, result.stderr)


def make_context(tmp_path, runner, sources=None):
    root = tmp_path / "source"
    root.mkdir(exist_ok=True)
    scratch = tmp_path / "scratch"
    scratch.mkdir(exist_ok=True)
    sources = (
        {"a.py": "def square(x: int) -> int:\n    return x * x\n"}
        if sources is None
        else sources
    )
    files = []
    for relative, content in sources.items():
        path = root / relative
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(content)
        language = "python" if path.suffix == ".py" else "java"
        files.append(SourceFile(path, relative, language, False, path.stat().st_size))
    return ScanContext(
        root, tuple(files), tuple(files), ("python",), "full", 30, scratch, runner
    )


def pyscn_data():
    return {
        "schema_version": 1,
        "summary": {
            "total_files": 1,
            "analyzed_files": 1,
            "skipped_files": 0,
            "health_score": 0,
            "clone_enabled": True,
            "dead_code_enabled": True,
            "duplication_score": 0,
            "code_duplication_percentage": 0,
            "clone_groups": 0,
            "dead_code_count": 0,
        },
        "complexity": {"raw_metrics": [{"file_path": "a.py"}], "errors": []},
        "clone": {
            "success": True,
            "clone_groups": [],
            "statistics": {"files_analyzed": 1, "total_clone_groups": 0},
        },
        "dead_code": {
            "errors": [],
            "files": [],
            "summary": {"total_findings": 0, "total_files": 1},
        },
    }


@pytest.mark.parametrize(
    "adapter",
    [analyze_ruff, analyze_python_types, analyze_maintainability, analyze_pyscn],
)
@pytest.mark.parametrize(
    "status,code",
    [
        ("timeout", None),
        ("missing", None),
        ("failed", None),
        ("output_limit", 0),
        ("ok", 2),
    ],
)
def test_execution_failure_never_clean(tmp_path, adapter, status, code):
    ctx = make_context(tmp_path, FakeRunner("", code, status))
    result = adapter(ctx)
    stages = result if isinstance(result, list) else [result]
    assert all(stage.status in ("timeout", "missing", "failed") for stage in stages)
    assert all(stage.metrics == {} and stage.analyzed_files == 0 for stage in stages)


@pytest.mark.parametrize(
    "adapter",
    [analyze_ruff, analyze_python_types, analyze_maintainability, analyze_pyscn],
)
@pytest.mark.parametrize(
    "text", ["", "not json", "null", '"wrong"', "{}", "[1]", '{"summary": []}']
)
def test_malformed_json_never_clean(tmp_path, adapter, text):
    result = adapter(make_context(tmp_path, FakeRunner(text)))
    stages = result if isinstance(result, list) else [result]
    assert all(stage.status == "failed" and stage.metrics == {} for stage in stages)


def test_ruff_real_zero_and_rule_location(tmp_path):
    clean = analyze_ruff(make_context(tmp_path, FakeRunner("[]")))
    assert clean.status == "ok" and clean.metrics["issue_count"] == 0
    issue = {
        "filename": "a.py",
        "location": {"row": 2, "column": 5},
        "code": "F821",
        "message": "Undefined name",
    }
    result = analyze_ruff(make_context(tmp_path, FakeRunner(json.dumps([issue]), 1)))
    assert result.status == "ok" and result.metrics["issue_count"] == 1
    assert (
        result.findings[0].path,
        result.findings[0].line,
        result.findings[0].rule,
    ) == ("a.py", 2, "ruff.F821")


@pytest.mark.parametrize(
    "filename,line,code",
    [
        ("../escape.py", 2, "F821"),
        ("a.py", True, "F821"),
        ("a.py", 0, "F821"),
        ("a.py", 2, None),
    ],
)
def test_ruff_rejects_wrong_diagnostic_fields(tmp_path, filename, line, code):
    item = {
        "filename": filename,
        "location": {"row": line, "column": 1},
        "code": code,
        "message": "message",
    }
    result = analyze_ruff(make_context(tmp_path, FakeRunner(json.dumps([item]), 1)))
    assert result.status == "failed"


def test_pyrefly_errors_warnings_and_ignored_target_config(tmp_path):
    diagnostics = [
        {
            "path": "a.py",
            "line": 1,
            "column": 1,
            "name": "bad-return",
            "severity": "error",
        },
        {
            "path": "a.py",
            "line": 2,
            "column": 1,
            "name": "unused-ignore",
            "severity": "warn",
        },
    ]
    runner = FakeRunner(json.dumps({"errors": diagnostics}), 1)
    ctx = make_context(tmp_path, runner)
    (ctx.root / "pyrefly.toml").write_text('preset = "off"\n')
    result = analyze_python_types(ctx)
    assert (
        result.status == "ok"
        and result.metrics["error_count"] == 1
        and result.metrics["warning_count"] == 1
    )
    command, kwargs = runner.calls[0]
    config = Path(command[command.index("--config") + 1])
    assert ctx.scratch in config.parents and kwargs["cwd"] == ctx.scratch
    assert "--skip-interpreter-query" in command and not config.exists()


@pytest.mark.parametrize(
    "diagnostic",
    [
        {
            "path": "a.py",
            "line": -1,
            "column": 1,
            "name": "bad-return",
            "severity": "error",
        },
        {
            "path": "other.py",
            "line": 1,
            "column": 1,
            "name": "bad-return",
            "severity": "error",
        },
        {"path": "a.py", "line": 1, "column": 1, "name": [], "severity": "error"},
    ],
)
def test_pyrefly_wrong_diagnostic_schema(tmp_path, diagnostic):
    result = analyze_python_types(
        make_context(tmp_path, FakeRunner(json.dumps({"errors": [diagnostic]}), 1))
    )
    assert result.status == "failed" and not result.metrics


def test_pyscn_zero_is_known_and_one_analysis_supplies_three_stages(tmp_path):
    runner = FakeRunner(json.dumps(pyscn_data()))
    ctx = make_context(tmp_path, runner)
    stages = analyze_pyscn(ctx)
    assert [stage.status for stage in stages] == ["ok", "ok", "ok"]
    assert stages[0].metrics == {"health_score": 0.0} and not stages[0].required
    assert stages[1].metrics == {"duplication_percent": 0.0, "clone_groups": 0}
    assert stages[2].metrics == {"issue_count": 0}
    assert sum("analyze" in command for command, _ in runner.calls) == 1
    command, kwargs = runner.calls[0]
    assert (
        command[command.index("--output") + 1] == "-" and kwargs["cwd"] == ctx.scratch
    )


def test_pyscn_stale_artifact_ignored(tmp_path):
    ctx = make_context(tmp_path, FakeRunner(""))
    reports = ctx.root / ".pyscn" / "reports"
    reports.mkdir(parents=True)
    (reports / "analyze_old.json").write_text(json.dumps(pyscn_data()))
    assert all(stage.status == "failed" for stage in analyze_pyscn(ctx))


@pytest.mark.parametrize(
    "field,value",
    [
        ("health_score", True),
        ("health_score", 101),
        ("health_score", None),
        ("health_score", float("nan")),
    ],
)
def test_pyscn_invalid_health_does_not_invalidate_independent_clones(
    tmp_path, field, value
):
    data = pyscn_data()
    data["summary"][field] = value
    stages = analyze_pyscn(make_context(tmp_path, FakeRunner(json.dumps(data))))
    assert stages[0].status == "failed" and stages[1].status == "ok"


@pytest.mark.parametrize(
    "field,value",
    [
        ("analyzed_files", 0),
        ("analyzed_files", 2),
        ("analyzed_files", True),
        ("skipped_files", -1),
        ("total_files", 2),
    ],
)
def test_pyscn_coverage_schema(tmp_path, field, value):
    data = pyscn_data()
    data["summary"][field] = value
    assert all(
        stage.status == "failed"
        for stage in analyze_pyscn(make_context(tmp_path, FakeRunner(json.dumps(data))))
    )


def test_pyscn_clone_metrics_and_locations(tmp_path):
    data = pyscn_data()
    data["summary"].update(clone_groups=1, code_duplication_percentage=75.5)
    data["clone"]["statistics"]["total_clone_groups"] = 1
    data["clone"]["clone_groups"] = [
        {
            "id": 0,
            "clones": [
                {"location": {"file_path": "a.py", "start_line": 1, "end_line": 3}},
                {"location": {"file_path": "a.py", "start_line": 5, "end_line": 7}},
            ],
        }
    ]
    stage = analyze_pyscn(make_context(tmp_path, FakeRunner(json.dumps(data))))[1]
    assert (
        stage.status == "ok"
        and stage.metrics["duplication_percent"] == 75.5
        and len(stage.findings) == 2
    )


def test_pyscn_component_failure_keeps_unknown(tmp_path):
    data = pyscn_data()
    data["clone"]["success"] = False
    stages = analyze_pyscn(make_context(tmp_path, FakeRunner(json.dumps(data))))
    assert (
        stages[0].status == "failed"
        and stages[1].status == "failed"
        and stages[2].status == "ok"
    )


def test_radon_informational_and_missing_file_unknown(tmp_path):
    stage = analyze_maintainability(
        make_context(
            tmp_path, FakeRunner('{"version": "6.0.1", "files": {"a.py": {"mi": 0}}}')
        )
    )
    assert (
        stage.status == "ok"
        and stage.metrics == {"average_mi": 0.0}
        and not stage.required
    )
    stage = analyze_maintainability(make_context(tmp_path, FakeRunner("{}")))
    assert stage.status == "failed" and not stage.metrics


_GENERIC_CONTROL = """from typing import Any, Generic, Never, TypeVar, overload
T = TypeVar("T")
class Container(Generic[T]):
    @overload
    def copy(self: "Container[Never]") -> "Container[Any]": ...
    @overload
    def copy(self: "Container[int]") -> "Container[int]": ...
    @overload
    def copy(self: "Container[float]") -> "Container[float]": ...
    def copy(self) -> "Container[Any]":
        return self
"""


@pytest.mark.parametrize("tool", ["ruff", "pyrefly", "pyscn", "radon"])
def test_native_clean_tool_pilot(tmp_path, tool):
    if shutil.which(tool) is None:
        pytest.skip(f"optional native pilot requires installed {tool}")
    adapter = {
        "ruff": analyze_ruff,
        "pyrefly": analyze_python_types,
        "pyscn": analyze_pyscn,
        "radon": analyze_maintainability,
    }[tool]
    result = adapter(make_context(tmp_path, native_runner))
    stages = result if isinstance(result, list) else [result]
    assert all(stage.status == "ok" for stage in stages), [
        (stage.id, stage.reason) for stage in stages
    ]
    assert all(stage.version for stage in stages)


def test_native_pyrefly_generic_regression_and_clean_control(tmp_path):
    """Pyright upstream #11731 specialized-self container/member control."""
    if shutil.which("pyrefly") is None:
        pytest.skip("optional native pilot requires installed pyrefly")
    bad = (
        _GENERIC_CONTROL
        + "\ndef example(value: Container[Any]) -> None:\n    value.copy().nonexistent_member()\n"
    )
    ctx = make_context(tmp_path, native_runner, {"a.py": bad})
    (ctx.root / "pyrefly.toml").write_text('preset = "off"\n')
    result = analyze_python_types(ctx)
    assert result.status == "ok" and result.metrics["error_count"] >= 1
    assert any(
        finding.rule == "pyrefly.missing-attribute" and finding.line == 14
        for finding in result.findings
    )
    clean = (
        _GENERIC_CONTROL
        + "\ndef example(value: Container[Any], concrete: Container[int]) -> None:\n    value.copy().copy()\n    concrete.copy().copy()\n"
    )
    (ctx.root / "a.py").write_text(clean)
    result = analyze_python_types(ctx)
    assert result.status == "ok" and result.metrics["error_count"] == 0


def test_native_pyscn_positive_clones_deadcode_and_nonmutation(tmp_path):
    if shutil.which("pyscn") is None:
        pytest.skip("optional native pilot requires installed pyscn")
    body = "".join(f"    result += value * {n}\n" for n in range(1, 16))
    source = (
        "def compute(value: int) -> int:\n    result = 0\n"
        + body
        + "    return result\n"
    )
    sources = {
        "a.py": source,
        "b.py": source,
        "dead.py": 'def dead() -> int:\n    return 1\n    print("unreachable")\n',
    }
    ctx = make_context(tmp_path, native_runner, sources)
    (ctx.root / "pyscn.toml").write_text("[analysis]\nclone_enabled = false\n")
    before = {
        path.relative_to(ctx.root): path.read_bytes()
        for path in ctx.root.rglob("*")
        if path.is_file()
    }
    stages = analyze_pyscn(ctx)
    assert all(stage.status == "ok" for stage in stages), [
        (stage.id, stage.reason) for stage in stages
    ]
    assert (
        stages[1].metrics["clone_groups"] >= 1
        and stages[1].metrics["duplication_percent"] > 0
    )
    assert (
        stages[2].metrics["issue_count"] >= 1
        and stages[2].findings[0].path == "dead.py"
    )
    after = {
        path.relative_to(ctx.root): path.read_bytes()
        for path in ctx.root.rglob("*")
        if path.is_file()
    }
    assert before == after and not (ctx.root / ".pyscn").exists()


@pytest.mark.parametrize(
    "source,expected_rule",
    [
        ('x: int = "bad"\n', "pyrefly.bad-assignment"),
        (
            'def f(x: int) -> int:\n    return x\nf("bad")\n',
            "pyrefly.bad-argument-type",
        ),
        ("def f(:\n    return 1\n", "pyrefly.parse-error"),
    ],
)
def test_native_pyrefly_representative_error_controls(tmp_path, source, expected_rule):
    if shutil.which("pyrefly") is None:
        pytest.skip("optional native pilot requires installed pyrefly")
    result = analyze_python_types(
        make_context(tmp_path, native_runner, {"a.py": source})
    )
    assert result.status == "ok" and result.metrics["error_count"] >= 1
    assert any(finding.rule == expected_rule for finding in result.findings)


def test_native_pyrefly_sibling_import_and_missing_dependency(tmp_path):
    if shutil.which("pyrefly") is None:
        pytest.skip("optional native pilot requires installed pyrefly")
    ctx = make_context(
        tmp_path,
        native_runner,
        {
            "a.py": "from b import square\nvalue: int = square(3)\n",
            "b.py": "def square(x: int) -> int:\n    return x * x\n",
        },
    )
    result = analyze_python_types(ctx)
    assert result.status == "ok" and result.metrics["error_count"] == 0
    (ctx.root / "a.py").write_text("import diff_gremlin_dependency_not_installed\n")
    result = analyze_python_types(ctx)
    assert result.status == "limited" and result.metrics["error_count"] >= 1
    assert "Imports unavailable" in result.reason


def test_pyscn_partial_coverage_is_visible(tmp_path):
    data = pyscn_data()
    data["summary"].update(total_files=2, skipped_files=1)
    ctx = make_context(
        tmp_path,
        FakeRunner(json.dumps(data)),
        {"a.py": "value = 1\n", "b.py": "value = 2\n"},
    )
    stages = analyze_pyscn(ctx)
    assert all(
        stage.status == "limited"
        and stage.analyzed_files == 1
        and stage.eligible_files == 2
        for stage in stages
    )


def test_pyscn_deadcode_invalid_summary_cannot_be_clean(tmp_path):
    data = pyscn_data()
    data["summary"]["dead_code_count"] = 1
    assert (
        analyze_pyscn(make_context(tmp_path, FakeRunner(json.dumps(data))))[2].status
        == "failed"
    )


def test_radon_api_missing_package_and_unsafe_metric(tmp_path):
    result = analyze_maintainability(make_context(tmp_path, FakeRunner("", 3)))
    assert result.status == "missing" and not result.required and not result.metrics
    for metric in [True, None, -1, 101, float("inf")]:
        report = {"version": "6.0.1", "files": {"a.py": {"mi": metric}}}
        result = analyze_maintainability(
            make_context(tmp_path, FakeRunner(json.dumps(report)))
        )
        assert result.status == "failed" and not result.metrics


def test_empty_python_inventory_is_not_passing(tmp_path):
    for adapter in [
        analyze_ruff,
        analyze_python_types,
        analyze_maintainability,
        analyze_pyscn,
    ]:
        runner = FakeRunner("[]")
        result = adapter(make_context(tmp_path, runner, {}))
        stages = result if isinstance(result, list) else [result]
        assert all(
            stage.status == "unsupported" and stage.metrics == {} for stage in stages
        )
        assert not runner.calls


@pytest.mark.parametrize("version", ["25.0.4.1", "1.24.0", "1.3.0-beta.2", "0.16.8"])
def test_tool_version_preserves_full_numeric_identity(tmp_path, version):
    calls = []

    def runner(command, **kwargs):
        calls.append((list(command), kwargs))
        return RunResult(tuple(command), 0, f"javac {version}\n")

    ctx = make_context(tmp_path, runner)
    assert tool_version(ctx, "javac") == version
    assert calls[0][0] == ["javac", "--version"]
    assert calls[0][1]["cwd"] == ctx.scratch


@pytest.mark.parametrize(
    "status,code", [("failed", 1), ("timeout", None), ("missing", None), ("ok", 1)]
)
def test_tool_version_rejects_failed_identity_output(tmp_path, status, code):
    def runner(command, **kwargs):
        return RunResult(tuple(command), code, "javac 25.0.4.1", status=status)

    assert tool_version(make_context(tmp_path, runner), "javac") == ""
