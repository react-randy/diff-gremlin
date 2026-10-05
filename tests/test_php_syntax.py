"""Native PHP parser transport, coverage and target non-execution controls."""

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from diff_gremlin.analyzers.php import tokens
from diff_gremlin.analyzers.php.syntax import analyze_php_syntax
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult
from diff_gremlin.process import run, trusted_path


def context(root: Path, sources: dict[str, str], runner=run) -> ScanContext:
    files = []
    for name, source in sources.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
        files.append(SourceFile(path, name, "php", False, path.stat().st_size))
    scratch = root.parent / (root.name + "-scratch")
    scratch.mkdir(exist_ok=True)
    return ScanContext(
        root, tuple(files), tuple(files), ("php",), "full", 10, scratch, runner
    )


@pytest.fixture
def native_php(tmp_path):
    if not shutil.which("php", path=trusted_path(tmp_path)):
        pytest.skip("Native trusted PHP required")


def test_native_parser_reports_modern_syntax_and_located_error(tmp_path, native_php):
    ctx = context(
        tmp_path,
        {
            "good.php": "<?php enum State:string {case Ready='ready';} function value():State {return State::Ready;}",
            "bad.php": "<?php\nfunction broken( {\n",
        },
    )
    result = analyze_php_syntax(ctx)
    assert result.status == "ok"
    assert result.analyzed_files == result.eligible_files == 2
    assert result.version.startswith("8.")
    assert [(f.path, f.line) for f in result.findings] == [("bad.php", 2)]


def test_native_target_code_configs_and_hostile_filename_never_execute(
    tmp_path, native_php
):
    marker = tmp_path / "executed"
    payload = f"<?php file_put_contents({json.dumps(str(marker))}, 'executed');"
    ctx = context(
        tmp_path,
        {
            "--flag ; $x.php": payload + " require 'vendor/autoload.php';",
            "vendor/autoload.php": payload,
        },
    )
    for name in ("php.ini", ".user.ini"):
        (tmp_path / name).write_text("auto_prepend_file=vendor/autoload.php")
    (tmp_path / "composer.json").write_text(
        json.dumps({"autoload": {"files": ["vendor/autoload.php"]}})
    )
    (tmp_path / "php").write_text("#!/bin/sh\ntouch executed\n")
    (tmp_path / "php").chmod(0o755)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    assert analyze_php_syntax(ctx).status == "ok"
    assert not marker.exists()
    assert all(p.read_bytes() == data for p, data in before.items())


def test_missing_parser_has_empty_metrics(tmp_path, monkeypatch):
    ctx = context(tmp_path, {"a.php": "<?php echo 1;"})
    monkeypatch.setattr(tokens, "php_executable", lambda _: None)
    stage = analyze_php_syntax(ctx)
    assert stage.status == "missing"
    assert stage.analyzed_files == 0 and stage.eligible_files == 1
    assert stage.metrics == {}


@pytest.mark.parametrize(
    "status, expected",
    [("timeout", "timeout"), ("output_limit", "limited"), ("failed", "failed")],
)
def test_transport_failures_are_not_clean(tmp_path, monkeypatch, status, expected):
    def runner(command, **kwargs):
        assert command[1] == "-n" and kwargs["cwd"] != tmp_path
        assert kwargs["timeout"] <= 10
        return RunResult(tuple(command), None, status=status)

    ctx = context(tmp_path, {"a.php": "<?php echo 1;"}, runner)
    monkeypatch.setattr(tokens, "php_executable", lambda _: "/trusted/php")
    result = analyze_php_syntax(ctx)
    assert result.status == expected
    assert result.analyzed_files == 0 and result.metrics == {}


@pytest.mark.parametrize(
    "mutation",
    ["invalid-json", "nonce", "hash", "tokens", "parse-line", "schema", "version"],
)
def test_invalid_native_output_is_rejected(tmp_path, native_php, mutation):
    def runner(command, **kwargs):
        result = run(command, **kwargs)
        if mutation == "invalid-json":
            return replace(result, stdout="not JSON")
        data = json.loads(result.stdout)
        if mutation == "nonce":
            data["nonce"] = "other"
        if mutation == "hash":
            data["sha256"] = "0" * 64
        if mutation == "tokens":
            data["tokens"].pop()
        if mutation == "parse-line":
            data.update(parse_error={"line": 999}, tokens=[])
        if mutation == "schema":
            data["schema"] = True
        if mutation == "version":
            data["version"] = "made up"
        return replace(result, stdout=json.dumps(data))

    result = analyze_php_syntax(context(tmp_path, {"a.php": "<?php echo 1;"}, runner))
    assert result.status == "failed" and result.analyzed_files == 0


def test_partial_failure_retains_located_parse_findings(tmp_path, native_php):
    calls = 0

    def runner(command, **kwargs):
        nonlocal calls
        calls += 1
        return (
            run(command, **kwargs)
            if calls == 1
            else RunResult(tuple(command), None, status="timeout")
        )

    result = analyze_php_syntax(
        context(
            tmp_path, {"a.php": "<?php broken( {", "b.php": "<?php echo 2;"}, runner
        )
    )
    assert result.status == "limited"
    assert result.analyzed_files == 1 and result.eligible_files == 2
    assert len(result.findings) == 1


def test_cumulative_deadline_stops_remaining_files(tmp_path, monkeypatch, native_php):
    ctx = context(tmp_path, {"a.php": "<?php echo 1;", "b.php": "<?php echo 2;"})
    clock = iter([0.0, 0.0, 0.0, 11.0])
    monkeypatch.setattr(tokens.time, "monotonic", lambda: next(clock))
    # Native runner uses time.monotonic too, so return validated native evidence captured first.
    captured = []

    def runner(command, **kwargs):
        data = json.loads(kwargs["input_text"])
        import base64
        import hashlib

        source = base64.b64decode(data["source"])
        captured.append(command)
        output = {
            "schema": 1,
            "nonce": data["nonce"],
            "sha256": hashlib.sha256(source).hexdigest(),
            "version": "8.3.6",
            "parse_error": None,
            "tokens": [
                ["T_OPEN_TAG", base64.b64encode(b"<?php ").decode()],
                ["T_STRING", base64.b64encode(source[6:]).decode()],
            ],
        }
        return RunResult(tuple(command), 0, json.dumps(output))

    result = analyze_php_syntax(replace(ctx, runner=runner))
    assert len(captured) == 1
    assert result.status == "limited" and result.analyzed_files == 1


def test_outside_or_symlink_sources_are_not_read(tmp_path, native_php):
    ctx = context(tmp_path, {"a.php": "<?php echo 1;"})
    external = tmp_path.parent / "outside.php"
    external.write_text("<?php echo 2;")
    ctx.files[0].path.unlink()
    ctx.files[0].path.symlink_to(external)
    stage = analyze_php_syntax(ctx)
    assert stage.status == "limited" and stage.analyzed_files == 0


def test_unknown_and_blade_languages_are_not_ordinary_php(tmp_path):
    ctx = context(tmp_path, {"a.blade.php": "<h1>{{value}}</h1>"})
    files = (replace(ctx.files[0], language="php-blade"),)
    assert analyze_php_syntax(replace(ctx, files=files)).status == "unsupported"


def test_native_large_inventoried_source_and_non_utf8_tokens(tmp_path, native_php):
    ctx = context(
        tmp_path,
        {
            "large.php": "<?php /*" + "a" * (4 * 1024 * 1024) + "*/ echo 1;",
            "bytes.php": "<?php echo 'value';",
        },
    )
    ctx.files[1].path.write_bytes(b"<?php echo 'latin\xff';")
    files = (
        ctx.files[0],
        replace(ctx.files[1], size_bytes=ctx.files[1].path.stat().st_size),
    )
    ctx = replace(ctx, files=files, production_files=files)
    result = analyze_php_syntax(ctx)
    assert result.status == "ok" and result.analyzed_files == 2


def test_oversized_inventory_entry_retains_explicit_gap(tmp_path, native_php):
    ctx = context(tmp_path, {"large.php": "<?php /*" + "a" * (8 * 1024 * 1024) + "*/"})
    result = analyze_php_syntax(ctx)
    assert result.status == "limited" and result.analyzed_files == 0
    assert "byte/path budget" in result.reason


@pytest.mark.parametrize("newline", ["\n", "\r\n", "\r"])
def test_native_php_newline_tokens_and_parse_errors(tmp_path, native_php, newline):
    ctx = context(
        tmp_path,
        {
            "good.php": newline.join(["<?php", "// comment", "  eval($x);"]),
            "bad.php": newline.join(["<?php", "// comment", "function broken( {"]),
        },
    )
    batch = tokens.collect_php_tokens(ctx, ctx.files)
    assert batch.status == "ok"
    observed = next(token for token in batch.files[0].tokens if token.kind == "T_EVAL")
    assert (observed.line, observed.column) == (3, 3)
    assert batch.files[1].parse_error_line == 3


@pytest.mark.parametrize("source", [b"<?php echo 100;", b"<?php"])
def test_source_size_changes_after_inventory_are_coverage_gaps(
    tmp_path, native_php, source
):
    ctx = context(tmp_path, {"a.php": "<?php echo 1;"})
    ctx.files[0].path.write_bytes(source)
    stage = analyze_php_syntax(ctx)
    assert stage.status == "limited" and stage.analyzed_files == 0
    assert stage.metrics == {}


def test_actual_read_stays_bounded_when_source_grows(tmp_path, monkeypatch):
    from diff_gremlin.analyzers.php.token_source import MAX_SOURCE

    ctx = context(tmp_path, {"a.php": "<?php echo 1;"})
    path = ctx.files[0].path
    path.write_bytes(b"x" * (MAX_SOURCE + 1024))
    original_open = Path.open
    requested = []

    class BoundedReader:
        def __enter__(self):
            self.stream = original_open(path, "rb")
            return self

        def __exit__(self, *_):
            self.stream.close()

        def read(self, size):
            requested.append(size)
            assert size == MAX_SOURCE + 1
            return self.stream.read(size)

    monkeypatch.setattr(Path, "open", lambda *_: BoundedReader())
    with pytest.raises(ValueError, match="byte budget"):
        tokens._source(ctx, ctx.files[0])
    assert requested == [MAX_SOURCE + 1]
