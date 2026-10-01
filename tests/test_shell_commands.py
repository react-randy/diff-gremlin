"""Independent command-string positives and ordinary cross-language dispatch."""

import json
from dataclasses import asdict

import pytest

from diff_gremlin.analyzers.execution import analyze_execution
from diff_gremlin.analyzers.shell import shell_observations
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.process import run


def context(tmp_path, sources):
    files = []
    languages = {".sh": "shell", ".py": "python", ".js": "javascript"}
    for name, text in sources.items():
        path = tmp_path / name
        path.write_text(text)
        files.append(
            SourceFile(path, name, languages[path.suffix], False, len(text.encode()))
        )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    return ScanContext(
        tmp_path,
        tuple(files),
        tuple(files),
        tuple(languages.values()),
        "full",
        10,
        scratch,
        run,
    )


@pytest.mark.parametrize(
    "command",
    [
        'bash -o pipefail -c "$SECRET"',
        'bash -O extglob -c "$SECRET"',
        'bash --rcfile "./path with spaces" -c "$SECRET"',
        'bash --init-file ./config -c "$SECRET"',
        'bash +e -c "$SECRET"',
        'bash +o errexit -c "$SECRET"',
        'bash -eo pipefail -c "$SECRET"',
        'bash --noprofile --norc -c "$SECRET"',
        'sh -o errexit -c "$SECRET"',
        'dash -c "$SECRET"',
        'bash +c "$SECRET"',
    ],
)
def test_native_interpreter_options_retain_command_string_observation(
    tmp_path, command
):
    ctx = context(tmp_path, {"sample.sh": "#!/bin/sh\n" + command + "\n"})
    findings, count, reason = shell_observations(ctx, ctx.files)
    assert count == 1 and not reason
    assert len(findings) == 1
    assert (findings[0].rule, findings[0].severity) == ("shell.command-string", "high")
    assert (findings[0].path, findings[0].line, findings[0].column) == (
        "sample.sh",
        2,
        1,
    )
    assert "$SECRET" not in json.dumps(asdict(findings[0]))


@pytest.mark.parametrize(
    "command",
    [
        'bash -- -c "$SECRET"',
        'bash ./script.sh -c "$SECRET"',
        'bash --rcfile ./config ./script.sh -c "$SECRET"',
        'bash --rcfile -c "$SECRET"',
        'bash --unknown -c "$SECRET"',
        'bash --command "$SECRET"',
        'printf "%s" "-c"',
    ],
)
def test_native_operand_and_unknown_option_boundaries_do_not_invent_execution(
    tmp_path, command
):
    ctx = context(tmp_path, {"sample.sh": "#!/bin/sh\n" + command + "\n"})
    findings, count, reason = shell_observations(ctx, ctx.files)
    assert count == 1 and not reason
    assert len(findings) == 1 and findings[0].severity == "info"
    assert findings[0].rule == "shell.command-call"


def test_equivalent_ordinary_dynamic_dispatch_remains_located_and_informational(
    tmp_path,
):
    ctx = context(
        tmp_path,
        {
            "sample.sh": '#!/bin/sh\ncommand=printf\n"$command" "%s" "$value"\n. "$support"\n',
            "sample.py": 'import subprocess\nsubprocess.run([tool, "%s", value])\n',
            "sample.js": 'const {spawn} = require("node:child_process");\nspawn(tool, ["%s", value]);\n',
        },
    )
    stage = analyze_execution(ctx)
    assert stage.status == "ok" and stage.analyzed_files == stage.eligible_files == 3
    assert stage.metrics["actionable_count"] == 0
    assert {f.rule for f in stage.findings} == {
        "shell.dynamic-command",
        "shell.dynamic-source",
        "python.process-call",
        "javascript.process-call",
    }
    assert all(f.severity == "info" and f.line > 0 and f.path for f in stage.findings)
    assert "unresolved" in stage.findings[0].message or "approximate" in stage.reason


def test_equivalent_command_string_boundaries_retain_high_observations(tmp_path):
    ctx = context(
        tmp_path,
        {
            "sample.sh": '#!/bin/sh\nsh -c "$SYNTHETIC_SECRET"\n',
            "sample.py": 'import subprocess\nsubprocess.run("SYNTHETIC_SECRET", shell=True)\n',
            "sample.js": 'const {exec} = require("node:child_process");\nexec("SYNTHETIC_SECRET");\n',
        },
    )
    stage = analyze_execution(ctx)
    assert stage.status == "ok" and stage.metrics["actionable_count"] == 3
    assert all(f.severity == "high" for f in stage.findings)
    assert "SYNTHETIC_SECRET" not in json.dumps(asdict(stage))
