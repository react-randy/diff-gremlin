"""Contextual Unicode/execution and redacted credential-pattern controls."""

import os
import shutil
import subprocess
from dataclasses import replace

import pytest

from diff_gremlin.analyzers.execution import analyze_execution
from diff_gremlin.analyzers.secrets import _analyze_patterns, analyze_secrets
from diff_gremlin.analyzers.unicode import analyze_unicode
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult


def runner(command, *, cwd, timeout, **kwargs):
    result = subprocess.run(
        command,
        cwd=cwd,
        env={"PATH": os.environ["PATH"], "LANG": "C.UTF-8", "HOME": str(cwd)},
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
            path.parent.mkdir(parents=True, exist_ok=True)
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


def test_import_comment_literal_and_safe_process_calls_are_not_actionable(context):
    source = """import subprocess as process
from subprocess import run as launch
# eval("example") and os.system("ignored")
example = 'exec("fixture")'
launch(["echo", "safe"], shell=False)
process.run(["echo", "safe"])
"""
    result = analyze_execution(context([("a.py", "python", source)]))
    assert result.status == "ok"
    assert result.metrics["call_count"] == 2 and result.metrics["actionable_count"] == 0
    assert all(f.severity == "info" for f in result.findings)


def test_python_actual_eval_alias_shell_and_unicode_pair_are_located(context):
    source = (
        "import subprocess as process\n# directional "
        + chr(0x202E)
        + '\neval("1+1")\nprocess.run("echo safe", shell=True)\n'
    )
    result = analyze_execution(context([("a.py", "python", source)]))
    rules = {finding.rule for finding in result.findings}
    assert {
        "python.eval",
        "python.shell-execution",
        "security.obfuscated-execution",
    } <= rules
    pairs = [f for f in result.findings if f.rule == "security.obfuscated-execution"]
    assert {f.line for f in pairs} == {3, 4}
    assert all("line 2" in f.message for f in pairs)


def test_unicode_bidi_isolates_and_legitimate_emoji_joiner(context):
    text = (
        'const emoji = "👩\u200d💻";\nconst plain = "سلام café";\n// '
        + chr(0x2066)
        + "direction"
        + chr(0x2069)
        + "\n"
    )
    result = analyze_unicode(context([("a.ts", "typescript", text)]))
    assert result.status == "ok"
    assert len(result.findings) == 2
    assert {f.symbol for f in result.findings} == {"U+2066", "U+2069"}
    assert {f.line for f in result.findings} == {3}
    zero = analyze_unicode(
        context([("b.py", "python", "value" + chr(0x200B) + " = 1\n")])
    )
    assert zero.findings[0].symbol == "U+200B" and zero.findings[0].column == 6


def test_cross_file_unicode_does_not_pair_execution(context):
    result = analyze_execution(
        context(
            [("a.py", "python", "# " + chr(0x202E)), ("b.py", "python", 'eval("1")')]
        )
    )
    assert not any(f.rule == "security.obfuscated-execution" for f in result.findings)


def test_js_actual_calls_ignore_import_comment_literal_decoys(context):
    if not shutil.which("tsc"):
        pytest.skip("Actual installed TypeScript parser required")
    source = """import { exec as execute, spawn } from "node:child_process";
// eval("ignored")
const example = 'Function("ignored")';
spawn("echo", ["safe"], {shell: false});
execute("echo safe");
eval("1+1");
setTimeout("alert(1)", 1);
"""
    result = analyze_execution(context([("a.ts", "typescript", source)]))
    assert result.status == "ok", result.reason
    assert result.metrics["call_count"] == 4
    assert result.metrics["actionable_count"] == 3
    assert {f.line for f in result.findings if f.severity == "high"} == {5, 6, 7}


def test_java_actual_calls_ignore_comment_string_examples(context):
    if not shutil.which("javac") or not shutil.which("java"):
        pytest.skip("Actual installed JDK parser required")
    source = """public class Main {
      // Runtime.getRuntime().exec("example");
      String example = "new ProcessBuilder(ignored)";
      void run() throws Exception { Runtime.getRuntime().exec(new String[]{"echo", "safe"}); }
    }"""
    result = analyze_execution(context([("Main.java", "java", source)]))
    assert result.status == "ok" and result.metrics["call_count"] == 1
    assert (
        result.findings[0].rule == "java.runtime-exec" and result.findings[0].line == 4
    )


@pytest.mark.parametrize(
    "name,language",
    [
        ("settings.env", "text"),
        ("settings.yml", "text"),
        ("settings.json", "text"),
        ("a.go", "go"),
        ("a.swift", "swift"),
        ("a.rs", "rust"),
    ],
)
def test_unquoted_env_yaml_json_and_generic_source_credentials(context, name, language):
    fake = "AbCdEf0123456789QrStUvWxyz"
    result = _analyze_patterns(context([(name, language, '"API_KEY": ' + fake + "\n")]))
    assert result.status == "limited"
    assert any(f.rule == "secret.credential-assignment" for f in result.findings)
    assert fake not in repr(result)
    assert result.metrics["history_scanned"] is False


@pytest.mark.parametrize(
    "prefix,length,rule",
    [
        ("gh" + "p_", 36, "secret.github-token"),
        ("gl" + "pat-", 20, "secret.gitlab-token"),
        ("AK" + "IA", 16, "secret.aws-access-key"),
        ("AI" + "za", 35, "secret.google-api-key"),
        ("npm" + "_", 36, "secret.npm-token"),
        ("sk" + "_live_", 24, "secret.stripe-key"),
    ],
)
def test_canonical_fake_provider_patterns_are_redacted(context, prefix, length, rule):
    fake = prefix + ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 4)[:length]
    result = _analyze_patterns(context([("configuration.txt", "text", fake)]))
    assert any(f.rule == rule for f in result.findings)
    assert fake not in repr(result)
    assert all(f.path == "configuration.txt" and f.line == 1 for f in result.findings)


def test_private_key_header_and_placeholder_controls(context):
    header = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"
    result = _analyze_patterns(
        context([("identity.txt", "text", header + "\nFAKE NONFUNCTIONAL FIXTURE\n")])
    )
    assert result.findings[0].rule == "secret.private-key"
    placeholders = 'API_KEY = "your_example_key_here"\npassword: changeme123456\ntoken: ${TOKEN_FROM_ENV}\n'
    result = _analyze_patterns(context([("settings.env", "text", placeholders)]))
    assert result.status == "limited" and not result.findings
    assert "does not establish" in result.reason


def test_unreadable_binary_large_coverage_is_visible(context):
    ctx = context(
        [
            ("missing.txt", "text", "nothing"),
            ("binary.dat", "text", "binary\x00"),
            ("large.txt", "text", "x"),
        ]
    )
    ctx.files[0].path.unlink()
    ctx = replace(
        ctx,
        files=(
            ctx.files[0],
            ctx.files[1],
            replace(ctx.files[2], size_bytes=2 * 1024 * 1024),
        ),
    )
    for analyzer in (_analyze_patterns, analyze_unicode):
        result = analyzer(ctx)
        assert result.status == "limited" and result.analyzed_files == 0
        assert set(result.metrics["skipped_paths"]) == {
            "missing.txt",
            "binary.dat",
            "large.txt",
        }


def test_unparseable_and_unsupported_execution_coverage(context):
    result = analyze_execution(
        context([("bad.py", "python", "def syntax("), ("a.rs", "rust", "fn main() {}")])
    )
    assert result.status == "limited" and result.analyzed_files == 0
    assert result.metrics["unsupported_languages"] == ["rust"]


def test_absent_detector_retains_honest_limited_fallback(context, monkeypatch):
    monkeypatch.setattr(
        "diff_gremlin.analyzers.secrets.trusted_executable", lambda *args: None
    )
    result = analyze_secrets(
        context([("a.env", "text", "TOKEN=your_example_key_here")])
    )
    assert result.status == "limited" and result.tool == "builtin-patterns"
    assert "does not establish" in result.reason


def test_live_gitleaks_canonical_pat_private_key_and_negative_control(context):
    if not shutil.which("gitleaks"):
        pytest.skip("Actual official fixture-validated Gitleaks required")
    pat = "gh" + "p_" + ("9Y7jQ2kW4mN6pR8sT0uV3xZ5aB1cD6eF8gH2")
    private_key = (
        "-----BEGIN "
        + "RSA PRIVATE KEY-----\n"
        + ("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" * 4)
        + "\n-----END RSA PRIVATE KEY-----\n"
    )
    result = analyze_secrets(
        context(
            [
                ("credential.env", "text", "GITHUB_TOKEN=" + pat + "\n"),
                ("identity.pem", "text", private_key),
            ]
        )
    )
    assert result.status == "ok", result.reason
    assert result.tool == "gitleaks" and result.version == "8.30.1"
    assert {"secret.github-pat", "secret.private-key"} <= {
        f.rule for f in result.findings
    }
    assert pat not in repr(result) and private_key not in repr(result)
    clean = analyze_secrets(
        context([("safe.env", "text", "TOKEN=your_example_key_here\n")])
    )
    assert clean.status == "ok" and clean.metrics["match_count"] == 0
    assert "does not establish" in clean.reason


def test_target_gitleaks_suppressions_are_disabled(context):
    if not shutil.which("gitleaks"):
        pytest.skip("Actual official fixture-validated Gitleaks required")
    pat = "gh" + "p_" + ("9Y7jQ2kW4mN6pR8sT0uV3xZ5aB1cD6eF8gH2")
    ctx = context(
        [("credential.env", "text", "GITHUB_TOKEN=" + pat + " # gitleaks:allow\n")]
    )
    (ctx.root / ".gitleaks.toml").write_text('title = "Disable all rules"\n')
    (ctx.root / ".gitleaksignore").write_text("credential.env:github-pat:1\n")
    result = analyze_secrets(ctx)
    assert result.status == "ok" and result.metrics["match_count"] > 0
    assert any(f.rule == "secret.github-pat" for f in result.findings)


@pytest.mark.parametrize(
    "state,code",
    [("timeout", None), ("missing", None), ("failed", 2), ("ok", 0), ("ok", 1)],
)
def test_gitleaks_missing_fresh_report_never_passes(context, state, code):
    if not shutil.which("gitleaks"):
        pytest.skip("Actual official fixture-validated Gitleaks required")
    ctx = context([("safe.env", "text", "TOKEN=your_example_key_here")])
    ctx = replace(
        ctx,
        runner=lambda command, **kwargs: RunResult(tuple(command), code, status=state),
    )
    (ctx.scratch / "report.json").write_text("[]")
    result = analyze_secrets(ctx)
    assert result.status in {"failed", "timeout", "missing"} and not result.metrics


def test_locally_defined_eval_and_shadowed_process_alias_are_not_api_claims(context):
    source = """def eval(value): return value
import subprocess as process
process = object()
eval("plain function")
"""
    result = analyze_execution(context([("a.py", "python", source)]))
    assert result.status == "ok" and result.metrics["actionable_count"] == 0


def test_gitleaks_malformed_report_and_rule_paths_never_pass(context):
    if not shutil.which("gitleaks"):
        pytest.skip("Actual official fixture-validated Gitleaks required")
    from pathlib import Path

    for report in (
        {},
        [
            {
                "RuleID": "github-pat",
                "File": "../outside",
                "StartLine": 1,
                "StartColumn": 1,
            }
        ],
    ):

        def fake(command, report=report, **kwargs):
            import json

            if "--report-path" in command:
                Path(command[command.index("--report-path") + 1]).write_text(
                    json.dumps(report)
                )
            return RunResult(tuple(command), 1)

        ctx = replace(context([("safe.env", "text", "nothing")]), runner=fake)
        result = analyze_secrets(ctx)
        assert result.status == "failed" and not result.metrics


def test_gitleaks_scans_lockfiles_with_credential_urls(context):
    if not shutil.which("gitleaks"):
        pytest.skip("Actual official fixture-validated Gitleaks required")
    import json

    pat = "gh" + "p_" + ("9Y7jQ2kW4mN6pR8sT0uV3xZ5aB1cD6eF8gH2")
    lock = json.dumps(
        {
            "packages": {
                "example": {
                    "resolved": "https://user:" + pat + "@registry.invalid/package"
                }
            }
        }
    )
    result = analyze_secrets(context([("package-lock.json", "text", lock)]))
    assert result.status == "ok" and result.analyzed_files == 1
    assert any(
        f.rule == "secret.github-pat" and f.path == "package-lock.json"
        for f in result.findings
    )
    assert pat not in repr(result)
    benign = analyze_secrets(
        context(
            [
                (
                    "package-lock.json",
                    "text",
                    '{"name":"benign","lockfileVersion":3,"packages":{}}',
                )
            ]
        )
    )
    assert benign.status == "ok" and benign.metrics["match_count"] == 0


def test_default_detector_example_stopword_is_preserved(context):
    if not shutil.which("gitleaks"):
        pytest.skip("Actual official fixture-validated Gitleaks required")
    example = "gh" + "p_" + ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    result = analyze_secrets(context([("example.env", "text", "TOKEN=" + example)]))
    # The official global stopword deliberately excludes alphabet-sequence examples.
    assert result.status == "ok" and not result.findings
    assert "does not establish" in result.reason


def test_direct_commonjs_process_call_is_parser_backed(context):
    if not shutil.which("tsc"):
        pytest.skip("Actual installed TypeScript parser required")
    result = analyze_execution(
        context(
            [("a.js", "javascript", 'require("node:child_process").exec("echo safe");')]
        )
    )
    assert result.status == "ok" and result.metrics["actionable_count"] == 1
    assert result.findings[0].rule == "javascript.shell-execution"
