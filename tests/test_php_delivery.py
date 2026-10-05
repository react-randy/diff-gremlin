"""Native runtime and adverse delivery controls must execute real trusted tools."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from diff_gremlin.process import trusted_path
from scripts import prepare_php_cli, verify_docker
from scripts.php_delivery_controls import CASES, validate_receipt


def test_private_php_wrapper_ignores_target_ini(tmp_path):
    binary = shutil.which("php", path=trusted_path())
    assert binary, "native delivery requires reviewed PHP"
    wrapper = tmp_path / "private bin/php"
    identity = prepare_php_cli.prepare(Path(binary), wrapper)
    assert identity["tokenizer"] and identity["phar"]
    marker = tmp_path / "EXECUTED"
    bootstrap = tmp_path / "bootstrap.php"
    bootstrap.write_text(f"<?php file_put_contents('{marker}', 'unsafe');")
    config = tmp_path / "php.ini"
    config.write_text(f"auto_prepend_file={bootstrap}\n")
    result = subprocess.run(
        [wrapper, "-r", "echo php_ini_loaded_file() === false ? 'no-ini' : 'unsafe';"],
        env={**os.environ, "PHPRC": str(config)},
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    assert result.stdout == "no-ini"
    assert not marker.exists()


def test_runtime_preparation_cannot_overwrite_system_php(tmp_path):
    binary = shutil.which("php", path=trusted_path())
    assert binary
    with pytest.raises(ValueError, match="overwrite"):
        prepare_php_cli.prepare(Path(binary), Path(binary))


@pytest.mark.parametrize("name,source,stage,status", CASES)
def test_native_adverse_php_receipt(tmp_path, name, source, stage, status):
    verify_docker.write_control(tmp_path)
    (tmp_path / "example.php").write_text(source)
    before = {
        p.relative_to(tmp_path): p.read_bytes()
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "diff_gremlin",
            "check",
            str(tmp_path),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    receipt = validate_receipt(result, stage, status)
    assert receipt["stage"] == stage
    after = {
        p.relative_to(tmp_path): p.read_bytes()
        for p in tmp_path.rglob("*")
        if p.is_file()
    }
    assert before == after, name
