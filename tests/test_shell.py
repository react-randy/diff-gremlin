"""Independent native and hostile controls for static Shell evidence."""

import json
import time
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from diff_gremlin.analyzers.shell import (
    analyze_shell_complexity,
    analyze_shell_syntax,
    parser,
    schema,
    shell_observations,
    source,
)
from diff_gremlin.analyzers.shell.dialect import dialect
from diff_gremlin.analyzers.shell.parser import installed_parser
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult
from diff_gremlin.process import run

# Counts fixed from the v1 contract: base 1, explicit branch contributions only.
DECISIONS = [
    ("if true; then :; elif false; then :; else :; fi", 3),
    ("for x in a b; do :; done; while true; do :; done; until false; do :; done", 4),
    ("select x in a b; do :; done; for ((i=0; i<2; i++)); do :; done", 3),
    ("case x in a|b) :;; c) :;; *) :;; esac", 3),
    ("case x in a|b) :;; esac", 1),
    ("case x in esac", 1),
    ("true && false || :", 3),
    ("[[ x == x && y == y || z == z ]]", 3),
    ("! true | false; (( x = a ? b : c )); (( x = a && b | c ))", 1),
    ("echo $(if true; then :; fi); cat <(while true; do :; done)", 3),
    ("printf '%s' 'if && eval'; # while true; do :; done\n:", 1),
    ("cat <<'EOF'\nif true; then eval x; fi\nEOF\n", 1),
    ("cat <<EOF\n$(if true; then :; fi)\nEOF\n", 2),
]


def context(tmp_path, files=None, runner=run):
    """Build a real inventoried snapshot without running any target bytes."""
    inputs = files if files is not None else {"a.sh": "#!/bin/bash\nprintf ok\n"}
    rows = []
    for name, text in inputs.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        language = "shell" if path.suffix == ".sh" else "python"
        rows.append(
            SourceFile(
                path, name, language, name.startswith("tests/"), len(text.encode())
            )
        )
    scratch = tmp_path / "scratch"
    scratch.mkdir(exist_ok=True)
    return ScanContext(
        tmp_path,
        tuple(rows),
        tuple(f for f in rows if not f.is_test),
        tuple(sorted({f.language for f in rows})),
        "full",
        5,
        scratch,
        runner,
    )


def native_tree(ctx):
    """Acquire trusted native AST output for independent schema corruption controls."""
    binary, reason = installed_parser(ctx)
    assert binary, reason
    text = ctx.files[0].path.read_text()
    result = run(
        [binary, "--to-json", "-ln=bash"],
        cwd=ctx.scratch,
        input_text=text,
        data_output=True,
        output_limit=schema.MAX_JSON_BYTES,
    )
    assert result.status == "ok" and result.returncode == 0
    return json.loads(result.stdout)


class ParserRunner:
    """Keep the real version boundary, but replace one AST process result."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if command[-1] == "--version":
            return RunResult(tuple(command), 0, "v3.14.1\n")
        return self.result


@pytest.mark.parametrize("body,expected", DECISIONS)
def test_native_independent_decision_counts(tmp_path, body, expected):
    ctx = context(tmp_path, {"a.sh": f"#!/bin/bash\nf() {{\n{body}\n}}\n"})
    stage = analyze_shell_complexity(ctx)
    assert stage.status == "ok", stage.reason
    assert stage.metrics["max_cc"] == expected
    assert stage.metrics["functions"] == 1
    assert stage.metrics["measure"] == "shell-ast-decision-complexity-v1"
    assert stage.metrics["function_rows"][0] == {
        "file": "a.sh",
        "function": "f",
        "line": 2,
        "cc": expected,
    }


@pytest.mark.parametrize(
    "shebang",
    [
        "#!/bin/sh",
        "#!/bin/dash",
        "#!/bin/bash",
        "#!/bin/mksh",
        "#!/usr/bin/env bash",
        "#!/usr/bin/env -S sh",
    ],
)
def test_native_declared_dialects(tmp_path, shebang):
    ctx = context(tmp_path, {"folder with spaces/a.sh": f"{shebang}\nf() {{ :; }}\n"})
    syntax = analyze_shell_syntax(ctx)
    assert syntax.status == "ok" and syntax.version == "3.14.1", syntax.reason
    assert syntax.analyzed_files == syntax.eligible_files == 1
    assert analyze_shell_complexity(ctx).metrics["max_cc"] == 1


@pytest.mark.parametrize(
    "shebang",
    [
        "",
        "#!/bin/zsh",
        "#!/bin/fish",
        "#!/usr/bin/env -i bash",
        "#!/bin/bash -e",
        "#!",
        "#!" + "x" * 260,
    ],
)
def test_unsupported_shebang_stays_incomplete(tmp_path, shebang):
    ctx = context(tmp_path, {"a.sh": f"{shebang}\nprintf ok\n"})
    stage = analyze_shell_syntax(ctx)
    assert (
        stage.status == "limited"
        and stage.analyzed_files == 0
        and stage.eligible_files == 1
    )
    assert "dialect" in stage.reason
    assert not stage.metrics


@pytest.mark.parametrize(
    "bad",
    [
        "if true; then :",
        "while true; do :",
        "case x in a) :;;",
        "echo 'unfinished",
        "cat <<EOF\nmissing\n",
    ],
)
def test_native_syntax_error_location_and_no_secret(tmp_path, bad):
    ctx = context(tmp_path, {"a.sh": "#!/bin/sh\n" + bad + "\n"})
    stage = analyze_shell_syntax(ctx)
    assert stage.status != "ok" and stage.analyzed_files == 0
    assert stage.findings[0].rule == "shell.syntax-error"
    assert stage.findings[0].line >= 2
    assert bad not in json.dumps(asdict(stage))


def test_nested_functions_get_own_rows_and_top_level_no_row(tmp_path):
    ctx = context(
        tmp_path,
        {
            "a.sh": "#!/bin/bash\nif true; then :; fi\nouter(){\nif true; then :; fi\ninner(){ while true; do :; done; }\n}\n"
        },
    )
    stage = analyze_shell_complexity(ctx)
    assert stage.status == "ok", stage.reason
    assert stage.metrics["function_rows"] == [
        {"file": "a.sh", "function": "outer", "line": 3, "cc": 2},
        {"file": "a.sh", "function": "inner", "line": 5, "cc": 2},
    ]


def test_native_syntax_scope_and_production_complexity(tmp_path):
    ctx = context(
        tmp_path,
        {
            "a.sh": "#!/bin/sh\nprintf ok\n",
            "tests/check.sh": "#!/bin/sh\nf(){ :; }\n",
            "a.py": "pass\n",
        },
    )
    assert analyze_shell_syntax(ctx).analyzed_files == 2
    stage = analyze_shell_complexity(ctx)
    assert (
        stage.analyzed_files == stage.eligible_files == 1
        and stage.metrics["functions"] == 0
    )
    ctx = replace(ctx, files=(ctx.files[-1],), production_files=(ctx.files[-1],))
    assert analyze_shell_syntax(ctx).status == "unsupported"
    assert shell_observations(ctx, ()) == ([], 0, "")


@pytest.mark.parametrize(
    "command,rule,severity",
    [
        ("printf ok", "shell.command-call", "info"),
        ("own_function", "shell.command-call", "info"),
        ("eval '$SECRET'", "shell.eval", "high"),
        ("'eval' value", "shell.eval", "high"),
        ("bash -c 'printf ok'", "shell.command-string", "high"),
        ('/bin/sh -ec "$SECRET"', "shell.command-string", "high"),
        ("bash -- -c", "shell.command-call", "info"),
        ("source ./fixed.sh", "shell.source", "info"),
        ('. "$path"', "shell.dynamic-source", "info"),
        ('"$command" value', "shell.dynamic-command", "info"),
        ("e\\val value", "shell.dynamic-command", "info"),
    ],
)
def test_native_calls_calibrated_without_argument_leak(
    tmp_path, command, rule, severity
):
    ctx = context(tmp_path, {"a.sh": "#!/bin/bash\n" + command + "\n"})
    findings, count, reason = shell_observations(ctx, ctx.files)
    assert count == 1 and not reason, reason
    assert len(findings) == 1 and (findings[0].rule, findings[0].severity) == (
        rule,
        severity,
    )
    assert (findings[0].line, findings[0].column) == (2, 1)
    assert "$SECRET" not in json.dumps([asdict(f) for f in findings])


def test_native_quotes_comments_heredocs_and_substitutions(tmp_path):
    source_text = "#!/bin/bash\n# eval nope\nprintf 'eval nope'\ncat <<'EOF'\neval nope\nEOF\ncat <<EOF\n$(eval \"$SECRET\")\nEOF\nprintf $(bash -c x)\ncat <(eval x)\n"
    ctx = context(tmp_path, {"a.sh": source_text})
    findings, count, reason = shell_observations(ctx, ctx.files)
    assert count == 1 and not reason, reason
    assert [f.rule for f in findings].count("shell.eval") == 2
    assert [f.rule for f in findings].count("shell.command-string") == 1
    assert len(findings) == 8


def test_partial_failure_preserves_actionable_findings(tmp_path):
    ctx = context(
        tmp_path,
        {
            "good.sh": '#!/bin/bash\neval "SYNTHETIC_SECRET_PAYLOAD"\n',
            "bad.sh": "#!/bin/bash\nif true; then :\n",
        },
    )
    findings, count, reason = shell_observations(ctx, ctx.files)
    assert count == 1 and reason and any(f.rule == "shell.eval" for f in findings)
    stage = analyze_shell_syntax(ctx)
    assert (
        stage.status == "limited"
        and stage.analyzed_files == 1
        and stage.eligible_files == 2
    )
    assert "SYNTHETIC_SECRET_PAYLOAD" not in json.dumps(asdict(stage))
    assert "SYNTHETIC_SECRET_PAYLOAD" not in json.dumps([asdict(f) for f in findings])


@pytest.mark.parametrize(
    "status,code",
    [
        ("missing", None),
        ("timeout", None),
        ("failed", None),
        ("output_limit", 0),
        ("ok", 1),
    ],
)
def test_process_failure_never_clean(tmp_path, status, code):
    runner = ParserRunner(
        RunResult(("shfmt",), code, stderr="SYNTHETIC_SECRET_PAYLOAD", status=status)
    )
    stage = analyze_shell_syntax(context(tmp_path, runner=runner))
    assert stage.status != "ok" and not stage.metrics and stage.analyzed_files == 0
    assert "SYNTHETIC_SECRET_PAYLOAD" not in json.dumps(asdict(stage))
    call, kwargs = runner.calls[-1]
    assert call[1:] == ["--to-json", "-ln=bash"]
    assert kwargs["data_output"] and kwargs["cwd"].name == "scratch"
    assert kwargs["input_text"].startswith("#!/bin/bash")


@pytest.mark.parametrize("version", ["v3.14.0", "3.14.1", "v3.14.1 malicious", ""])
def test_wrong_version_never_invokes_parser(tmp_path, version):
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return RunResult(tuple(command), 0, version)

    stage = analyze_shell_syntax(context(tmp_path, runner=runner))
    assert stage.status == "failed" and stage.analyzed_files == 0 and len(calls) == 1


def test_missing_parser(tmp_path, monkeypatch):
    monkeypatch.setattr(parser, "trusted_executable", lambda *args: None)
    stage = analyze_shell_syntax(context(tmp_path))
    assert stage.status == "missing" and not stage.metrics and stage.eligible_files == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_type",
        "unknown_field",
        "missing_body",
        "position",
        "wrong_scalar",
        "operator",
    ],
)
def test_schema_drift_never_clean(tmp_path, mutation):
    ctx = context(tmp_path, {"a.sh": "#!/bin/bash\nf(){ true && false; }\n"})
    tree = native_tree(ctx)
    function = tree["Stmts"][0]["Cmd"]
    if mutation == "unknown_type":
        function["Type"] = "FutureFunction"
    elif mutation == "unknown_field":
        function["Future"] = 1
    elif mutation == "missing_body":
        del function["Body"]
    elif mutation == "position":
        function["Pos"]["Line"] = 999
    elif mutation == "wrong_scalar":
        function["Parens"] = "true"
    elif mutation == "operator":
        function["Body"]["Cmd"]["Stmts"][0]["Cmd"]["Op"] = "future"
    text = json.dumps(tree)
    stage = analyze_shell_complexity(
        replace(ctx, runner=ParserRunner(RunResult(("shfmt",), 0, text)))
    )
    assert stage.status != "ok" and not stage.metrics and stage.analyzed_files == 0


@pytest.mark.parametrize(
    "text", ["", "{", "{}", '{"Type":"File"}', '{"Type":"File","Type":"File"}']
)
def test_missing_or_duplicate_root_evidence_is_incomplete(tmp_path, text):
    ctx = context(tmp_path, runner=ParserRunner(RunResult(("shfmt",), 0, text)))
    stage = analyze_shell_syntax(ctx)
    assert stage.status != "ok" and not stage.metrics and stage.analyzed_files == 0


@pytest.mark.parametrize(
    "limit_name,limit", [("MAX_NODES", 2), ("MAX_DEPTH", 3), ("MAX_JSON_BYTES", 16)]
)
def test_ast_resource_caps(tmp_path, monkeypatch, limit_name, limit):
    ctx = context(tmp_path)
    tree = native_tree(ctx)
    monkeypatch.setattr(schema, limit_name, limit)
    with pytest.raises(ValueError):
        schema.decode(json.dumps(tree), ctx.files[0].path.read_text())


def test_file_and_source_caps_and_changed_unreadable_input(tmp_path, monkeypatch):
    ctx = context(tmp_path, {"a.sh": "#!/bin/sh\n:\n", "b.sh": "#!/bin/sh\n:\n"})
    monkeypatch.setattr(parser, "MAX_FILES", 1)
    stage = analyze_shell_syntax(ctx)
    assert (
        stage.status == "limited"
        and stage.analyzed_files == 1
        and stage.eligible_files == 2
    )
    assert "omitted 1" in stage.reason
    monkeypatch.setattr(source, "MAX_SOURCE_BYTES", 2)
    assert analyze_shell_syntax(ctx).analyzed_files == 0
    monkeypatch.setattr(source, "MAX_SOURCE_BYTES", 1024 * 1024)
    ctx.files[0].path.write_text("changed")
    ctx.files[1].path.unlink()
    stage = analyze_shell_syntax(ctx)
    assert stage.status != "ok" and stage.analyzed_files == 0


def test_hostile_config_path_and_source_never_execute(tmp_path, monkeypatch):
    marker = tmp_path / "EXECUTED"
    ctx = context(tmp_path, {"a.sh": f"#!/bin/sh\n. ./payload.sh\ntouch '{marker}'\n"})
    (tmp_path / ".editorconfig").write_text("[*]\nshell_variant = zsh\n")
    (tmp_path / "payload.sh").write_text(f"touch '{marker}'\n")
    fake = tmp_path / "shfmt"
    fake.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    stage = analyze_shell_syntax(ctx)
    assert stage.status == "ok", stage.reason
    assert not marker.exists()


def test_native_deadline_and_output_boundary(tmp_path):
    ctx = context(tmp_path)
    binary, reason = installed_parser(ctx)
    assert binary, reason
    start = time.monotonic()
    result = run(
        [binary, "--to-json", "-ln=bash"],
        cwd=ctx.scratch,
        input_text="#!/bin/bash\n" + "printf ok\n" * 10_000,
        output_limit=1024,
        data_output=True,
        timeout=5,
    )
    assert result.status == "output_limit" and time.monotonic() - start < 6
    result = run(
        [binary, "--to-json", "-ln=bash"],
        cwd=ctx.scratch,
        input_text="#!/bin/bash\n" + "printf ok\n" * 100_000,
        output_limit=schema.MAX_JSON_BYTES,
        data_output=True,
        timeout=0.000001,
    )
    assert result.status == "timeout" and time.monotonic() - start < 6


def test_empty_source_decoder_and_unicode_byte_locations(tmp_path):
    assert schema.decode('{"Type":"File"}', "")["_kind"] == "File"
    ctx = context(tmp_path, {"a.sh": "#!/bin/bash\nprintf 'é'\neval x\n"})
    findings, count, reason = shell_observations(ctx, ctx.files)
    assert count == 1 and not reason and findings[-1].line == 3


def test_dialect_map_is_owned_and_strict():
    assert dialect("#!/usr/bin/env -S mksh\n") == "mksh"
    with pytest.raises(ValueError):
        dialect("#!/usr/bin/env bash -e\n")


@pytest.mark.parametrize(
    "shebang,body",
    [
        ("#!/bin/mksh", "x=${ echo hi;}\n"),
        (
            "#!/bin/bash",
            "declare -A x=([foo]=bar); arr=(a b); let x++; echo ${arr[0]:1:2} ${x/foo/bar} ${x@Q}; echo @(foo|bar); coproc worker { printf hi; }; time printf hi;\n",
        ),
        (
            "#!/bin/bash",
            'printf "$(cat <<EOF\n$(cat <<INNER\nhello\nINNER\n)\nEOF\n)"\n',
        ),
    ],
)
def test_native_structural_containers_arrays_and_nested_heredocs(
    tmp_path, shebang, body
):
    stage = analyze_shell_syntax(context(tmp_path, {"a.sh": shebang + "\n" + body}))
    assert stage.status == "ok" and stage.analyzed_files == 1, stage.reason
    assert stage.scope == "all-inventoried-shell"


def test_symlink_input_rejected_and_target_not_read(tmp_path):
    ctx = context(tmp_path)
    actual = tmp_path / "actual"
    ctx.files[0].path.rename(actual)
    ctx.files[0].path.symlink_to(actual)
    stage = analyze_shell_syntax(ctx)
    assert stage.status != "ok" and stage.analyzed_files == 0


def test_conditional_omission_is_schema_failure(tmp_path):
    ctx = context(tmp_path, {"a.sh": "#!/bin/bash\nf(){ if true; then :; fi; }\n"})
    tree = native_tree(ctx)
    del tree["Stmts"][0]["Cmd"]["Body"]["Cmd"]["Stmts"][0]["Cmd"]["Cond"]
    result = RunResult(("shfmt",), 0, json.dumps(tree))
    stage = analyze_shell_complexity(replace(ctx, runner=ParserRunner(result)))
    assert stage.status != "ok" and not stage.metrics


def test_hotspot_threshold_retains_real_finding(tmp_path):
    body = "if true; then :; fi; " * 10
    stage = analyze_shell_complexity(
        context(tmp_path, {"a.sh": f"#!/bin/bash\nf(){{ {body}}}\n"})
    )
    assert stage.status == "ok", stage.reason
    assert stage.metrics["max_cc"] == 11 and len(stage.findings) == 1
    assert stage.findings[0].rule == "shell.high-complexity"
    assert stage.findings[0].symbol == "f" and stage.findings[0].severity == "medium"


def test_missing_function_name_is_schema_failure(tmp_path):
    ctx = context(tmp_path, {"a.sh": "#!/bin/bash\nf(){ :; }\n"})
    tree = native_tree(ctx)
    del tree["Stmts"][0]["Cmd"]["Name"]["Value"]
    stage = analyze_shell_complexity(
        replace(ctx, runner=ParserRunner(RunResult(("shfmt",), 0, json.dumps(tree))))
    )
    assert stage.status != "ok" and not stage.metrics


def test_parser_diagnostic_huge_location_cannot_raise_or_leak(tmp_path):
    text = "9" * 5000 + ":1: SYNTHETIC_SECRET_PAYLOAD"
    ctx = context(tmp_path, runner=ParserRunner(RunResult(("shfmt",), 1, stderr=text)))
    stage = analyze_shell_syntax(ctx)
    assert stage.status != "ok" and stage.findings[0].line == 0
    assert "SYNTHETIC_SECRET_PAYLOAD" not in json.dumps(asdict(stage))


class Clock:
    """Advance controlled wall time only at verified process boundaries."""

    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        return self.value


class BudgetRunner(ParserRunner):
    """Observe each remaining deadline without changing the AST evidence."""

    def __init__(self, result, clock, version_seconds=1, file_seconds=2):
        super().__init__(result)
        self.clock = clock
        self.version_seconds = version_seconds
        self.file_seconds = file_seconds

    def __call__(self, command, **kwargs):
        result = super().__call__(command, **kwargs)
        self.clock.value += (
            self.version_seconds if command[-1] == "--version" else self.file_seconds
        )
        return result


def budget_context(tmp_path, monkeypatch, timeout=3):
    """Use independently validated AST and equal source files for partial-budget tests."""
    text = "#!/bin/bash\neval 'SYNTHETIC_SECRET_PAYLOAD'\n"
    ctx = context(tmp_path, {"a.sh": text, "b.sh": text, "c.sh": text})
    output = json.dumps(native_tree(ctx))
    clock = Clock()
    runner = BudgetRunner(RunResult(("shfmt",), 0, output), clock)
    monkeypatch.setattr(parser.time, "monotonic", clock.monotonic)
    return replace(ctx, timeout=timeout, runner=runner), runner, clock, output


def test_cumulative_deadline_includes_version_and_retains_findings(
    tmp_path, monkeypatch
):
    ctx, runner, _, _ = budget_context(tmp_path, monkeypatch)
    findings, count, reason = shell_observations(ctx, ctx.files)
    assert count == 1 and len(findings) == 1 and findings[0].rule == "shell.eval"
    assert "cumulative time budget exhausted; omitted 2 eligible files" in reason
    assert [kwargs["timeout"] for _, kwargs in runner.calls] == [3, 2]
    assert "SYNTHETIC_SECRET_PAYLOAD" not in json.dumps([asdict(f) for f in findings])


def test_version_probe_can_consume_entire_deadline(tmp_path, monkeypatch):
    ctx, runner, _, _ = budget_context(tmp_path, monkeypatch)
    runner.version_seconds = 3
    stage = analyze_shell_syntax(ctx)
    assert (
        stage.status == "limited"
        and stage.analyzed_files == 0
        and stage.eligible_files == 3
    )
    assert "time budget exhausted; omitted 3 eligible files" in stage.reason
    assert len(runner.calls) == 1


def test_no_deadline_remaining_never_invokes_a_tool(tmp_path):
    runner = ParserRunner(RunResult(("shfmt",), 0, ""))
    stage = analyze_shell_syntax(replace(context(tmp_path, runner=runner), timeout=0))
    assert stage.status == "limited" and stage.analyzed_files == 0
    assert "time budget exhausted; omitted 1 eligible files" in stage.reason
    assert runner.calls == []


def test_cumulative_source_bytes_keep_prior_tree_and_counts(tmp_path, monkeypatch):
    ctx, runner, _, _ = budget_context(tmp_path, monkeypatch, timeout=30)
    monkeypatch.setattr(parser, "MAX_TOTAL_SOURCE_BYTES", ctx.files[0].size_bytes)
    stage = analyze_shell_complexity(ctx)
    assert (
        stage.status == "limited"
        and stage.analyzed_files == 1
        and stage.eligible_files == 3
    )
    assert stage.metrics["functions"] == 0 and len(runner.calls) == 2
    assert "source byte budget exhausted; omitted 2 eligible files" in stage.reason


def test_cumulative_output_bytes_keep_prior_findings(tmp_path, monkeypatch):
    ctx, runner, _, output = budget_context(tmp_path, monkeypatch, timeout=30)
    monkeypatch.setattr(parser, "MAX_TOTAL_OUTPUT_BYTES", len(output.encode()))
    findings, count, reason = shell_observations(ctx, ctx.files)
    assert count == 1 and findings[0].rule == "shell.eval" and len(runner.calls) == 2
    assert "output byte budget exhausted; omitted 2 eligible files" in reason
    assert runner.calls[-1][1]["output_limit"] == len(output.encode())


def test_output_exhaustion_mid_file_cannot_accept_oversized_tree(tmp_path, monkeypatch):
    ctx, runner, _, output = budget_context(tmp_path, monkeypatch, timeout=30)
    monkeypatch.setattr(parser, "MAX_TOTAL_OUTPUT_BYTES", len(output.encode()) + 1)
    stage = analyze_shell_syntax(ctx)
    assert (
        stage.status == "limited"
        and stage.analyzed_files == 1
        and stage.eligible_files == 3
    )
    assert runner.calls[-1][1]["output_limit"] == 1
    assert "output byte limit exceeded: b.sh" in stage.reason
    assert "output byte budget exhausted; omitted 1 eligible files" in stage.reason


def test_native_cumulative_deadline_bounds_selected_files(tmp_path, monkeypatch):
    files = {f"{i}.sh": "#!/bin/bash\nprintf ok\n" for i in range(20)}
    clock = Clock()
    timeouts = []

    def timed_native_runner(command, **kwargs):
        result = run(command, **kwargs)
        timeouts.append(kwargs["timeout"])
        clock.value += 1 if command[-1] == "--version" else 2
        return result

    # Control only the adapter's clock; native process deadlines stay real.
    monkeypatch.setattr(parser, "time", SimpleNamespace(monotonic=clock.monotonic))
    ctx = replace(context(tmp_path, files), timeout=3, runner=timed_native_runner)
    stage = analyze_shell_syntax(ctx)
    assert stage.status == "limited" and stage.analyzed_files == 1
    assert stage.eligible_files == 20 and timeouts == [3, 2]
    assert "time budget exhausted; omitted 19 eligible files" in stage.reason
