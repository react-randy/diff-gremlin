"""PHP uses the same native provenance and omission controls as JS clones."""

import json
from dataclasses import replace
from pathlib import Path

import test_polyglot

from diff_gremlin.analyzers.php.duplication import analyze_php_duplication
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.process import run

context = test_polyglot.context

LONG = (
    "<?php\nfunction compute($input) {\n"
    + "".join(f"    $value{i} = $input * {i + 2};\n" for i in range(30))
    + "    return $value0;\n}\n"
)


def test_native_php_clone_identity_locations(context):
    result = analyze_php_duplication(
        context(
            [
                ("a.php", "php", LONG),
                ("b.php", "php", LONG),
            ]
        )
    )
    assert result.id == "php.duplication.jscpd"
    assert result.status == "ok", result.reason
    assert result.version == "4.2.3"
    assert result.analyzed_files == result.eligible_files == 2
    assert result.metrics["clone_groups"] > 0
    assert {f.path for f in result.findings} == {"a.php", "b.php"}
    assert all(f.line > 0 for f in result.findings)


def test_native_php_short_file_has_explicit_gap(context):
    result = analyze_php_duplication(context([("a.php", "php", "<?php echo 1;\n")]))
    assert result.status == "limited"
    assert result.analyzed_files == 0 and result.eligible_files == 1
    assert stage_score(result) is None


def test_php_clones_do_not_measure_frontend_or_tests(context):
    ctx = context(
        [
            ("a.php", "php", LONG),
            ("ui.tsx", "typescript", LONG),
            ("tests/SampleTest.php", "php", LONG),
        ]
    )
    ctx = replace(ctx, production_files=ctx.files[:2])
    result = analyze_php_duplication(ctx)
    assert result.status == "ok", result.reason
    assert result.analyzed_files == result.eligible_files == 1
    assert result.metrics["analyzed_paths"] == ["a.php"]


def test_php_clone_report_cannot_switch_native_grammar(context):
    def tamper(command, **kwargs):
        result = run(command, **kwargs)
        path = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        report = json.loads(path.read_text())
        report["requested_formats"] = ["typescript"]
        path.write_text(json.dumps(report))
        return result

    result = analyze_php_duplication(context([("a.php", "php", LONG)], tamper))
    assert result.status == "failed" and not result.metrics
    assert "grammars" in result.reason
