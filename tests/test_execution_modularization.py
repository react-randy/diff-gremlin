"""Execution observer regressions across language and failure boundaries."""

import json
import subprocess
from dataclasses import replace

import pytest

from diff_gremlin.analyzers.execution import analyze_execution
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult
from diff_gremlin.process import trusted_path


def runner(command, *, cwd, timeout, **kwargs):
    result = subprocess.run(
        command,
        cwd=cwd,
        env={"PATH": trusted_path(cwd), "LANG": "C.UTF-8", "HOME": str(cwd)},
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return RunResult(tuple(command), result.returncode, result.stdout, result.stderr)


@pytest.fixture
def context(tmp_path):
    root, scratch = tmp_path / "root", tmp_path / "scratch"
    root.mkdir()
    scratch.mkdir()

    def make(sources):
        files = []
        for name, language, text in sources:
            path = root / name
            path.write_text(text, encoding="utf-8")
            files.append(SourceFile(path, name, language, False, path.stat().st_size))
        return ScanContext(
            root,
            tuple(files),
            tuple(files),
            tuple({f.language for f in files}),
            "full",
            30,
            scratch,
            runner,
        )

    return make


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            'from builtins import eval as inspect\ninspect("private argument")\n',
            [("python.eval", "high", 2, "builtins.eval")],
        ),
        (
            'import subprocess as task\ndef local(task):\n    task.run("private argument")\n'
            'task.run(["echo", "private argument"], shell=False)\n',
            [("python.process-call", "info", 4, "subprocess.run")],
        ),
        (
            "class Owner:\n    eval = lambda value: value\n"
            '    def run(self):\n        return eval("private argument")\n',
            [("python.eval", "high", 4, "eval")],
        ),
        (
            'def run(value=eval("private argument")):\n    return value\n',
            [("python.eval", "high", 1, "eval")],
        ),
        (
            'values = {eval: eval("private argument") for eval in callbacks}\n'
            'eval("private argument")\n',
            [("python.eval", "high", 2, "eval")],
        ),
        (
            'import subprocess\nsubprocess.getoutput("private argument")\n'
            'compile("private argument", "file", "eval")\n',
            [
                ("python.shell-execution", "high", 2, "subprocess.getoutput"),
                ("python.dynamic-compile", "info", 3, "compile"),
            ],
        ),
    ],
)
def test_python_lexical_observations_preserve_locations_and_safe_labels(
    context, source, expected
):
    result = analyze_execution(context([("sample.py", "python", source)]))
    assert result.status == "ok" and result.analyzed_files == result.eligible_files == 1
    assert [(f.rule, f.severity, f.line, f.symbol) for f in result.findings] == expected
    assert all(f.path == "sample.py" and f.column > 0 for f in result.findings)
    assert "private argument" not in repr(result)


@pytest.mark.parametrize("failure", ["syntax", "missing", "encoding", "large"])
def test_python_failed_file_preserves_other_observations_and_coverage(context, failure):
    ctx = context(
        [
            ("good.py", "python", 'eval("private argument")\n'),
            ("bad.py", "python", "def syntax(" if failure == "syntax" else "pass\n"),
        ]
    )
    if failure == "missing":
        ctx.files[1].path.unlink()
    elif failure == "encoding":
        ctx.files[1].path.write_bytes(b"\xff")
    elif failure == "large":
        ctx = replace(
            ctx, files=(ctx.files[0], replace(ctx.files[1], size_bytes=1024 * 1024 + 1))
        )
    result = analyze_execution(ctx)
    assert (
        result.status == "limited"
        and result.analyzed_files == 1
        and result.eligible_files == 2
    )
    assert [f.rule for f in result.findings] == ["python.eval"]
    assert "bad.py" in result.reason and "private argument" not in repr(result)


@pytest.mark.parametrize("failure", ["timeout", "failed", "malformed", "outside"])
def test_js_parser_failure_preserves_python_observations(context, failure):
    ctx = context(
        [
            ("good.py", "python", 'eval("private argument")\n'),
            ("sample.ts", "typescript", 'eval("private argument");\n'),
        ]
    )

    def fail(command, **kwargs):
        if failure in {"timeout", "failed"}:
            return RunResult(
                tuple(command), None if failure == "timeout" else 2, status=failure
            )
        data = (
            {}
            if failure == "malformed"
            else {
                "files": [str(ctx.files[1].path.resolve())],
                "parse_errors": 0,
                "findings": [
                    {
                        "path": "/outside",
                        "line": 1,
                        "column": 1,
                        "rule": "javascript.eval",
                        "severity": "high",
                    }
                ],
            }
        )
        return RunResult(tuple(command), 0, json.dumps(data))

    result = analyze_execution(replace(ctx, runner=fail))
    assert (
        result.status == "limited"
        and result.analyzed_files == 1
        and result.eligible_files == 2
    )
    assert [f.rule for f in result.findings] == ["python.eval"]
    assert "JS/TS" in result.reason


def test_native_mixed_language_aggregation_keeps_unicode_pairs_separate(context):
    ctx = context(
        [
            (
                "sample.py",
                "python",
                "# " + chr(0x202E) + '\neval("private argument")\n',
            ),
            ("sample.ts", "typescript", 'eval("private argument");\n'),
            (
                "Main.java",
                "java",
                "class Main { void run() throws Exception { "
                'Runtime.getRuntime().exec(new String[]{"echo", "private argument"}); } }',
            ),
            ("other.rs", "rust", "fn main() {}"),
        ]
    )
    result = analyze_execution(ctx)
    assert (
        result.status == "limited"
        and result.analyzed_files == result.eligible_files == 3
    )
    assert result.metrics == {
        "call_count": 3,
        "actionable_count": 3,
        "unsupported_languages": ["rust"],
    }
    assert [f.rule for f in result.findings] == [
        "python.eval",
        "javascript.eval",
        "java.runtime-exec",
        "security.obfuscated-execution",
    ]
    assert result.findings[-1].path == "sample.py" and result.findings[-1].line == 2
    assert "private argument" not in repr(result)
