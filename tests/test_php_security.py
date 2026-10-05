"""Native parser security rules with risky and benign context controls."""

from dataclasses import replace

import pytest
from test_php_syntax import context
from test_php_syntax import native_php as native_php

from diff_gremlin.analyzers.php.security import analyze_php_security
from diff_gremlin.domain.process import RunResult
from diff_gremlin.process import run


@pytest.mark.parametrize(
    "source,rule,line",
    [
        ("<?php\neval($_GET['code']);", "eval", 2),
        ("<?php\nunserialize($_POST['data']);", "request-unserialize", 2),
        ("<?php\n$data=$_GET['data'];\nunserialize($data);", "request-unserialize", 3),
        ('<?php\nsystem("echo $value");', "dynamic-shell", 2),
        ('<?php\nexec("echo ".$value);', "dynamic-shell", 2),
        ("<?php\n`echo $value`;", "dynamic-shell", 2),
        ('<?php\n$db->query("SELECT * FROM t WHERE id=".$id);', "concatenated-sql", 2),
        ('<?php\nDB::raw("SELECT ".$column);', "concatenated-sql", 2),
        ("<?php\nextract($_GET);", "extract", 2),
        ("<?php\nrequire $_GET['path'];", "variable-include", 2),
        ("<?php\ninclude($file);", "variable-include", 2),
        (
            "<?php\nunserialize($_POST['data'], ['allowed_classes'=>false, 'allowed_classes'=>true]);",
            "request-unserialize",
            2,
        ),
        ("<?php\nexec('echo ' . escapeshellarg($safe) . $unsafe);", "dynamic-shell", 2),
        ("<?php\n\\unserialize($_POST['data']);", "request-unserialize", 2),
    ],
)
def test_native_risky_constructs_are_located(tmp_path, native_php, source, rule, line):
    result = analyze_php_security(context(tmp_path, {"risk.php": source}))
    assert result.status == "ok"
    assert result.analyzed_files == result.eligible_files == 1
    assert [
        (finding.rule, finding.path, finding.line) for finding in result.findings
    ] == [("security.php." + rule, "risk.php", line)]
    assert all(
        finding.column > 0 and finding.confidence == "medium"
        for finding in result.findings
    )
    assert "no whole-program dataflow" in result.reason


@pytest.mark.parametrize(
    "source",
    [
        "<?php // eval($_GET['x']);\n/* system(\"$v\"); */ $text='unserialize($_GET)';",
        "<?php unserialize('a:0:{}');",
        "<?php unserialize($_POST['x'], ['allowed_classes'=>false]);",
        "<?php unserialize($_POST['x'], array('allowed_classes'=>false));",
        "<?php system('echo ' . escapeshellarg($_GET['x']));",
        "<?php exec('printf hello');",
        "<?php $db->prepare('SELECT * FROM t WHERE id=?')->execute([$id]);",
        "<?php $db->query('SELECT * FROM t WHERE id=?', [$id]);",
        "<?php include 'literal.php'; require_once('other.php');",
        "<?php include __DIR__ . '/literal.php';",
        "<?php system('echo ' . \\escapeshellarg($_GET['x']));",
        "<?php $service->system($value); $service->unserialize($_GET);",
        "<?php function system_clone($value) { return $value; } system_clone($value);",
    ],
)
def test_native_benign_controls(tmp_path, native_php, source):
    result = analyze_php_security(context(tmp_path, {"benign.php": source}))
    assert result.status == "ok" and result.analyzed_files == 1
    assert result.findings == []


def test_malformed_source_is_security_gap_but_good_file_survives(tmp_path, native_php):
    result = analyze_php_security(
        context(
            tmp_path, {"bad.php": "<?php eval( {", "good.php": "<?php eval($source);"}
        )
    )
    assert result.status == "limited"
    assert result.eligible_files == 2 and result.analyzed_files == 1
    assert [finding.path for finding in result.findings] == ["good.php"]


def test_partial_transport_keeps_security_findings(tmp_path, native_php):
    count = 0

    def runner(command, **kwargs):
        nonlocal count
        count += 1
        return (
            run(command, **kwargs)
            if count == 1
            else RunResult(tuple(command), None, status="output_limit")
        )

    result = analyze_php_security(
        context(
            tmp_path,
            {"first.php": "<?php eval($source);", "second.php": "<?php echo 1;"},
            runner,
        )
    )
    assert result.status == "limited" and result.analyzed_files == 1
    assert len(result.findings) == 1


def test_rule_messages_do_not_expose_source_arguments(tmp_path, native_php):
    secret = "sensitive-table-literal"
    result = analyze_php_security(
        context(tmp_path, {"a.php": f'<?php $db->query("{secret}".$user);'})
    )
    assert len(result.findings) == 1
    assert secret not in result.findings[0].message


def test_security_top_level_payload_is_never_executed(tmp_path, native_php):
    marker = tmp_path / "marker"
    result = analyze_php_security(
        context(
            tmp_path,
            {"a.php": f"<?php file_put_contents('{marker}', 'bad'); eval($_GET['x']);"},
        )
    )
    assert result.status == "ok" and len(result.findings) == 1
    assert not marker.exists()


def test_security_without_php_is_unsupported(tmp_path):
    ctx = context(tmp_path, {"a.php": "<?php echo 1;"})
    assert analyze_php_security(replace(ctx, files=())).status == "unsupported"


def test_security_token_deadline_preserves_earlier_complete_file(
    tmp_path, native_php, monkeypatch
):
    from diff_gremlin.analyzers.php import security, security_rules

    ctx = context(tmp_path, {"a.php": "<?php eval($x);", "b.php": "<?php eval($y);"})
    batch = security.collect_php_tokens(ctx, ctx.files)
    monkeypatch.setattr(security, "collect_php_tokens", lambda *_: batch)
    clock = iter([0.0, *([0.0] * 6), 11.0])
    monkeypatch.setattr(security_rules.time, "monotonic", lambda: next(clock))
    result = analyze_php_security(ctx)
    assert result.status == "limited" and result.analyzed_files == 1
    assert len(result.findings) == 1
    assert "time budget" in result.reason
