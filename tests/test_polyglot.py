"""Failure controls and actual-tool fixtures for bounded polyglot evidence."""

import json
import os
import shutil
import subprocess

import pytest

from diff_gremlin.analyzers.java.structure import analyze_java_structure
from diff_gremlin.analyzers.java.types import analyze_java_types
from diff_gremlin.analyzers.javascript.duplication import analyze_js_duplication
from diff_gremlin.analyzers.javascript.installed import trusted_executable
from diff_gremlin.analyzers.javascript.lint import analyze_js_lint
from diff_gremlin.analyzers.javascript.types import analyze_ts_types
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult


def runner(command, *, cwd, timeout, **kwargs):
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": "C.UTF-8",
        "HOME": str(cwd),
    }
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return RunResult(
            tuple(command), result.returncode, result.stdout, result.stderr
        )
    except FileNotFoundError:
        return RunResult(tuple(command), None, status="missing")


@pytest.fixture
def context(tmp_path):
    root, scratch = tmp_path / "source", tmp_path / "scratch"
    root.mkdir()
    scratch.mkdir()

    def make(sources, run=runner):
        files = []
        for name, language, text in sources:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            files.append(SourceFile(path, name, language, False, path.stat().st_size))
        return ScanContext(
            root,
            tuple(files),
            tuple(files),
            tuple(sorted({f.language for f in files})),
            "full",
            30,
            scratch,
            run,
        )

    return make


def require_tools(*names):
    if any(not shutil.which(name) for name in names):
        pytest.skip("Actual installed tool fixture requires " + ", ".join(names))


@pytest.mark.parametrize(
    "adapter",
    [
        analyze_js_lint,
        analyze_ts_types,
        analyze_js_duplication,
        analyze_java_structure,
        analyze_java_types,
    ],
)
def test_empty_scope_is_explicitly_skipped(context, adapter):
    result = adapter(context([]))
    assert result.status == "skipped"
    assert result.analyzed_files == 0 and result.metrics == {}


def test_target_executable_is_rejected(context, monkeypatch):
    ctx = context([("a.ts", "typescript", "export const n = 1;")])
    binary = ctx.root / "bin" / "tsc"
    binary.parent.mkdir()
    binary.write_text("hostile")
    binary.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary.parent))
    assert trusted_executable(ctx, "tsc") is None
    assert analyze_ts_types(ctx).status == "missing"


@pytest.mark.parametrize(
    "state,code,stdout",
    [
        ("timeout", None, ""),
        ("missing", None, ""),
        ("failed", 2, ""),
        ("ok", 2, ""),
        ("ok", 0, "null"),
        ("ok", 0, "{}"),
        ("ok", 0, "[]"),
    ],
)
@pytest.mark.parametrize(
    "adapter",
    [
        analyze_js_lint,
        analyze_ts_types,
        analyze_js_duplication,
        analyze_java_structure,
        analyze_java_types,
    ],
)
def test_tool_failures_never_become_clean(context, adapter, state, code, stdout):
    require_tools("eslint", "tsc", "jscpd", "javac", "java")
    ctx = context(
        [
            ("a.ts", "typescript", "export const n = 1;"),
            ("Main.java", "java", "class Main {}"),
        ],
        lambda command, **kwargs: RunResult(tuple(command), code, stdout, status=state),
    )
    result = adapter(ctx)
    # Silent javac exit 0 is its documented success output; other empty JSON is invalid.
    if adapter == analyze_java_types and state == "ok" and code == 0 and not stdout:
        return
    assert result.status in {"failed", "missing", "timeout"}
    assert not result.metrics


def test_typescript_true_zero_errors_and_dependency_limit(context):
    require_tools("node", "tsc")
    clean = analyze_ts_types(
        context([("good.ts", "typescript", "export const answer: number = 42;")])
    )
    assert clean.status == "ok" and clean.metrics["error_count"] == 0
    assert clean.version == "6.0.3"
    bad = analyze_ts_types(
        context([("bad.ts", "typescript", 'export const answer: number = "bad";')])
    )
    assert bad.status == "ok" and bad.metrics["error_count"] == 1
    assert any(
        f.rule == "TS2322" and f.path == "bad.ts" and f.line == 1 for f in bad.findings
    )
    missing = analyze_ts_types(
        context(
            [
                (
                    "missing.ts",
                    "typescript",
                    'import { value } from "unprovided-package"; export {value};',
                )
            ]
        )
    )
    assert missing.status == "limited" and missing.metrics["dependency_count"] > 0


def test_project_configs_and_wrappers_cannot_execute(context):
    require_tools("node", "tsc", "eslint", "jscpd", "javac", "java")
    ctx = context(
        [
            ("good.ts", "typescript", "export const value: number = 1;"),
            ("Main.java", "java", "public class Main {}"),
        ]
    )
    sentinel = ctx.root / "executed"
    (ctx.root / "eslint.config.cjs").write_text(
        'require("fs").writeFileSync('
        + json.dumps(str(sentinel))
        + ', "bad"); throw new Error("hostile");'
    )
    (ctx.root / "tsconfig.json").write_text(
        '{"compilerOptions":{"plugins":[{"name":"hostile-plugin"}]},"extends":"missing-config"}'
    )
    plugin = ctx.root / "node_modules" / "hostile-plugin"
    plugin.mkdir(parents=True)
    (plugin / "index.js").write_text(
        'require("fs").writeFileSync(' + json.dumps(str(sentinel)) + ', "bad");'
    )
    (ctx.root / ".jscpd.json").write_text('{"reporters":["hostile-reporter"]}')
    for name in ("mvnw", "gradlew"):
        path = ctx.root / name
        path.write_text("#!/bin/sh\ntouch " + str(sentinel) + "\n")
        path.chmod(0o755)
    before = {p.name: p.read_bytes() for p in ctx.root.iterdir() if p.is_file()}
    results = [
        adapter(ctx)
        for adapter in (
            analyze_js_lint,
            analyze_ts_types,
            analyze_js_duplication,
            analyze_java_structure,
            analyze_java_types,
        )
    ]
    assert results[0].status == "ok"
    assert results[1].status == "ok" and results[4].status == "ok"
    assert not sentinel.exists()
    assert before == {p.name: p.read_bytes() for p in ctx.root.iterdir() if p.is_file()}


def test_eslint_preserves_custom_rule_intent(context):
    require_tools("node", "eslint")
    source = """export function compare(value: any) {
    var unused = 1;
    let duplicate = 2;
    if (value == duplicate) { throw "literal"; }
    const self = value; self = self;
    return Function("return 1");
    }
    """
    result = analyze_js_lint(context([("a.ts", "typescript", source)]))
    assert result.status == "ok", result.reason
    rules = {finding.rule for finding in result.findings}
    assert {
        "@typescript-eslint/no-explicit-any",
        "@typescript-eslint/no-unused-vars",
        "no-var",
        "prefer-const",
        "eqeqeq",
        "no-throw-literal",
        "no-const-assign",
        "no-self-assign",
    } <= rules
    assert result.metrics["issue_count"] == len(result.findings)
    clean = analyze_js_lint(
        context([("good.ts", "typescript", "export const answer = 42;")])
    )
    assert clean.status == "ok" and clean.metrics["issue_count"] == 0


def test_jscpd_fresh_zero_and_actual_clones(context):
    require_tools("node", "jscpd")
    source = (
        "export function compute(input: number): number {\n"
        + "".join(f" const value{i} = input * {i + 2};\n" for i in range(30))
        + " return value0;\n}\n"
    )
    clean = analyze_js_duplication(context([("a.ts", "typescript", source)]))
    assert clean.status == "ok" and clean.metrics["duplication_percent"] == 0
    clones = analyze_js_duplication(
        context([("a.ts", "typescript", source), ("b.ts", "typescript", source)])
    )
    assert clones.status == "ok", clones.reason
    assert (
        clones.metrics["duplication_percent"] == 50
        and clones.metrics["clone_groups"] == 1
    )
    assert {finding.path for finding in clones.findings} == {"a.ts", "b.ts"}


def test_stale_jscpd_artifact_is_ignored(context):
    require_tools("node", "jscpd")
    ctx = context(
        [("a.ts", "typescript", "export const value = 1;")],
        lambda command, **kwargs: RunResult(tuple(command), 0),
    )
    old = ctx.scratch / "jscpd-report.json"
    old.write_text(
        '{"statistics":{"total":{"percentage":0,"sources":1,"clones":0}},"duplicates":[]}'
    )
    result = analyze_js_duplication(ctx)
    assert result.status == "failed" and result.metrics == {}
    assert old.exists()


def test_java_modern_ast_ignores_comment_and_string_decoys(context):
    require_tools("javac", "java")
    source = r"""public record Pair<T>(T first, T second) {
      // class Decoy { void fake() { Runtime.getRuntime().exec("bad"); } }
      public String text() { return "class Another { ProcessBuilder(\"bad\") }"; }
      public void run() throws Exception { Runtime.getRuntime().exec(new String[]{"echo", "safe"}); }
      class Nested { public int value() { return 1; } }
    }"""
    result = analyze_java_structure(context([("Pair.java", "java", source)]))
    assert result.status == "ok" and result.metrics["error_count"] == 0
    assert result.metrics["type_count"] == 2 and result.metrics["method_count"] == 3
    calls = [f for f in result.findings if f.rule == "java.runtime-exec"]
    assert len(calls) == 1 and calls[0].line == 4
    broken = analyze_java_structure(
        context([("Broken.java", "java", "class Broken { void x( }")])
    )
    assert broken.status == "ok" and broken.metrics["error_count"] > 0
    assert any(f.rule == "java.syntax" for f in broken.findings)


def test_java_standalone_types_clean_error_and_missing_dependencies(context):
    require_tools("javac", "java")
    clean = analyze_java_types(
        context(
            [("Good.java", "java", "public class Good { int value() { return 1; } }")]
        )
    )
    assert clean.status == "ok" and clean.metrics["error_count"] == 0
    bad = analyze_java_types(
        context(
            [("Bad.java", "java", 'public class Bad { int value() { return "bad"; } }')]
        )
    )
    assert bad.status == "ok" and bad.metrics["error_count"] > 0
    assert bad.findings[0].path == "Bad.java"
    missing = analyze_java_types(
        context(
            [
                (
                    "External.java",
                    "java",
                    "import absent.Dependency; public class External { Dependency value; }",
                )
            ]
        )
    )
    assert missing.status == "limited" and missing.metrics["dependency_count"] > 0


@pytest.mark.parametrize(
    "total",
    [
        {"percentage": 0, "sources": 0, "clones": 0},
        {"percentage": 0, "sources": 2, "clones": 0},
        {"percentage": 101, "sources": 1, "clones": 0},
        {"percentage": 0, "sources": 1, "clones": 1},
        {"percentage": True, "sources": 1, "clones": 0},
    ],
)
def test_current_jscpd_schema_and_file_count_must_be_valid(context, total):
    require_tools("node", "jscpd")
    from pathlib import Path

    def fake(command, **kwargs):
        if "--output" in command:
            report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
            report.parent.mkdir()
            report.write_text(
                json.dumps({"statistics": {"total": total}, "duplicates": []})
            )
        return RunResult(tuple(command), 0)

    result = analyze_js_duplication(
        context([("a.ts", "typescript", "export const value=1;")], fake)
    )
    assert result.status == "failed" and not result.metrics


def test_java_reflective_and_unsafe_vocabulary_requires_actual_calls(context):
    require_tools("javac", "java")
    source = """class Main {
      // Unsafe.getUnsafe(); Class.forName("decoy");
      String fixture = "engine.eval(ignored)";
      void inspect() throws Exception { Unsafe.getUnsafe(); Class.forName("java.lang.String"); engine.eval("1+1"); }
    }"""
    result = analyze_java_structure(context([("Main.java", "java", source)]))
    assert result.status == "ok"
    assert {f.rule for f in result.findings} == {
        "java.unsafe-api",
        "java.reflective-load",
        "java.script-eval",
    }
    assert {f.line for f in result.findings} == {4}
