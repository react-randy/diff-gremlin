"""Native snapshot types, adversarial autoloads and receipt corruption controls."""

import json
from dataclasses import replace

import pytest
import test_polyglot

from diff_gremlin.analyzers.php.type_output import debug_document, diagnostics
from diff_gremlin.analyzers.php.types import analyze_php_types
from diff_gremlin.domain.process import RunResult
from diff_gremlin.policy.metrics import stage_score

context = test_polyglot.context


def test_native_local_type_error_and_namespaced_resolution(context):
    ctx = context(
        [
            (
                "A.php",
                "php",
                '<?php namespace Demo; class A { public function value(): int { return "wrong"; } }\n',
            ),
            (
                "B.php",
                "php",
                "<?php namespace Demo; function useA(A $a): int { return $a->value(); }\n",
            ),
        ]
    )
    stage = analyze_php_types(ctx)
    assert stage.status == "ok", stage.reason
    assert stage.version == "2.2.15" and stage.metrics["level"] == 5
    assert stage.analyzed_files == stage.eligible_files == 2
    assert stage.metrics["error_count"] == 1
    assert [(f.rule, f.path, f.line) for f in stage.findings] == [
        ("phpstan.return.type", "A.php", 1)
    ]


def test_native_undefined_symbols_remain_located_and_limited(context):
    ctx = context(
        [("job.php", "php", "<?php class Job extends \\Illuminate\\Queue\\Job {}\n")]
    )
    stage = analyze_php_types(ctx)
    assert stage.status == "limited", stage.reason
    assert stage.metrics["unresolved_symbols"] > 0
    assert stage_score(stage) is None and "framework/vendor" in stage.reason
    assert all(f.path == "job.php" and f.line == 1 for f in stage.findings)


def test_native_project_and_ancestor_autoloads_never_execute(context, tmp_path):
    marker = tmp_path / "EXECUTED"
    evil = "<?php file_put_contents(" + json.dumps(str(marker)) + ', "oops");\n'
    ctx = context(
        [("a.php", "php", evil + "function add(int $a): int { return $a + 1; }\n")]
    )
    for name in ("vendor/autoload.php", "bootstrap.php", "autoload.php"):
        p = ctx.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(evil)
    (ctx.root / "phpstan.neon").write_text(
        "parameters:\n    bootstrapFiles:\n        - bootstrap.php\n"
    )
    (ctx.root / "composer.json").write_text(
        json.dumps({"autoload": {"files": ["bootstrap.php"]}})
    )
    (ctx.root / "php.ini").write_text(
        "auto_prepend_file=" + str(ctx.root / "bootstrap.php")
    )
    before = {p: p.read_bytes() for p in ctx.root.rglob("*") if p.is_file()}
    stage = analyze_php_types(ctx)
    assert stage.status == "ok", stage.reason
    assert not marker.exists()
    assert before == {p: p.read_bytes() for p in ctx.root.rglob("*") if p.is_file()}


def test_native_progress_covers_more_than_ten_files(context):
    ctx = context(
        [
            (f"{i}.php", "php", f"<?php function f{i}(): int {{ return {i}; }}\n")
            for i in range(12)
        ]
    )
    stage = analyze_php_types(ctx)
    assert stage.status == "ok", stage.reason
    assert stage.analyzed_files == 12 and stage.metrics["error_count"] == 0


@pytest.mark.parametrize("prefix", ["", "foreign.php\n", "0.php\n0.php\n"])
def test_fake_empty_json_cannot_establish_source_coverage(context, prefix):
    ctx = context([("a.php", "php", "<?php function good(): int { return 1; }\n")])
    ctx = replace(
        ctx,
        runner=lambda command, **kw: RunResult(
            tuple(command),
            0,
            prefix + '{"totals":{"errors":0,"file_errors":0},"files":{},"errors":[]}',
        ),
    )
    result = analyze_php_types(ctx)
    assert result.status == "failed" and result.metrics == {}


def test_missing_php_tools_are_a_required_gap(context, monkeypatch):
    from diff_gremlin.analyzers.php import types

    monkeypatch.setattr(types, "trusted_executable", lambda *_: None)
    stage = analyze_php_types(context([("a.php", "php", "<?php echo 1;\n")]))
    assert stage.status == "missing" and stage.required and not stage.metrics


def test_invalid_native_location_and_counter_never_clean(context):
    ctx = context([("a.php", "php", "<?php echo 1;\n")])
    locations = {ctx.files[0].path: ctx.files[0]}
    with pytest.raises(ValueError, match="foreign"):
        diagnostics(
            json.dumps(
                {
                    "totals": {"errors": 0, "file_errors": 0},
                    "files": {"foreign.php": {}},
                    "errors": [],
                }
            ),
            locations,
            0,
        )
    with pytest.raises(ValueError, match="inventory"):
        debug_document(
            str(ctx.files[0].path) + "\n" + str(ctx.files[0].path) + "\n{}", locations
        )


@pytest.mark.parametrize("operation", ["require", "include"])
@pytest.mark.parametrize("include_path", ["vendor/autoload.php", "helper.php"])
def test_native_snapshot_include_paths_are_gaps(context, operation, include_path):
    sources = [("entry.php", "php", f"<?php {operation} '{include_path}';\n")]
    if include_path == "helper.php":
        sources.append(
            ("helper.php", "php", "<?php function helper(): int { return 1; }\n")
        )
    stage = analyze_php_types(context(sources))
    assert stage.status == "limited", stage.reason
    assert (
        stage.metrics["error_count"] == 0 and stage.metrics["unresolved_includes"] == 1
    )
    assert stage.metrics["unresolved_symbols"] == 0
    assert stage_score(stage) is None
    assert [(f.rule, f.path, f.line, f.severity) for f in stage.findings] == [
        (f"phpstan.{operation}.fileNotFound", "entry.php", 1, "low")
    ]
