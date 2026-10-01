"""Negative controls for bounded execution and analyzer environment isolation."""

import json
import os
import shutil
import sys
import time
from pathlib import Path

import pytest

from diff_gremlin.process import run


def python(code, **kwargs):
    return run([sys.executable, "-c", code], **kwargs)


def test_completed_nonzero_is_not_execution_failure():
    result = python("import sys; print('diagnostic'); sys.exit(3)")
    assert result.status == "ok"
    assert result.returncode == 3
    assert result.stdout == "diagnostic\n"


def test_default_environment_drops_tokens_configuration_and_repo_path(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("GH_TOKEN", "fake-secret-token")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("NODE_OPTIONS", "--require ./evil.js")
    monkeypatch.setenv("PATH", f".:{tmp_path}:{os.environ['PATH']}")
    result = python("import json,os;print(json.dumps(dict(os.environ)))", cwd=tmp_path)
    env = json.loads(result.stdout)
    assert "GH_TOKEN" not in env
    assert "PYTHONPATH" not in env
    assert "NODE_OPTIONS" not in env
    assert "." not in env["PATH"].split(os.pathsep)
    assert str(tmp_path) not in env["PATH"].split(os.pathsep)
    assert env["HOME"] != os.environ["HOME"]
    assert not Path(env["HOME"]).exists()


def test_repository_executable_is_never_selected(tmp_path, monkeypatch):
    wrapper = tmp_path / "git"
    wrapper.write_text("#!/bin/sh\nexit 99\n")
    wrapper.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert run(["git", "--version"], cwd=tmp_path).returncode == 0
    assert run([str(wrapper)], cwd=tmp_path).status == "missing"
    assert run(["./git"], cwd=tmp_path).status == "missing"


def test_shared_output_budget_and_timeout():
    result = python(
        "import os;\nwhile True: os.write(1,b'x'*4096);os.write(2,b'y'*4096)",
        output_limit=8192,
    )
    assert result.status == "output_limit"
    assert len(result.stdout) + len(result.stderr) <= 8192
    start = time.monotonic()
    result = python("import time;time.sleep(20)", timeout=0.15)
    assert result.status == "timeout"
    assert time.monotonic() - start < 2


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group lifecycle")
def test_timeout_kills_descendants(tmp_path):
    marker = tmp_path / "survived"
    code = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',sys.argv[1]]);time.sleep(20)"
    child = f"import time;from pathlib import Path;time.sleep(0.4);Path({str(marker)!r}).write_text('alive')"
    result = run([sys.executable, "-c", code, child], timeout=0.1)
    assert result.status == "timeout"
    time.sleep(0.5)
    assert not marker.exists()


def test_missing_launch_failure_and_redaction(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "fake-secret-token")
    assert run(["diff-gremlin-absent-tool"]).status == "missing"
    invalid = tmp_path / "invalid"
    invalid.write_text("not an executable")
    invalid.chmod(0o644)
    assert run([str(invalid)]).status == "failed"
    result = python(
        "import os,sys;print(os.environ['PRIVATE_TOKEN']);print('https://user:pass@example.test/x',file=sys.stderr)",
        env={"PRIVATE_TOKEN": "fake-secret-token"},
    )
    assert "fake-secret-token" not in result.stdout + result.stderr + repr(result.args)
    assert "user:pass" not in result.stderr


def test_large_input_is_drained_without_pipe_deadlock():
    payload = "x" * 1000000
    result = python("import sys;d=sys.stdin.read();print(len(d))", input_text=payload)
    assert result.stdout == "1000000\n"


@pytest.mark.parametrize(
    "kwargs", [{"timeout": 0}, {"timeout": float("nan")}, {"output_limit": 0}]
)
def test_bounds_are_required(kwargs):
    with pytest.raises(ValueError):
        run([sys.executable], **kwargs)


def test_python_startup_cannot_import_target_sitecustomize(tmp_path):
    marker = tmp_path / "executed"
    (tmp_path / "sitecustomize.py").write_text(
        f"from pathlib import Path;Path({str(marker)!r}).write_text('unsafe')"
    )
    assert python("print('safe')", cwd=tmp_path).stdout == "safe\n"
    assert not marker.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX file-size resource boundary")
def test_acquisition_resource_launcher_limits_child_files(tmp_path):
    from diff_gremlin.process import _execute

    output = tmp_path / "oversized"
    result = _execute(
        [sys.executable, "-c", f"open({str(output)!r},'wb').write(b'x'*10000)"],
        file_limit=1024,
    )
    assert result.status == "ok" and result.returncode != 0
    assert output.stat().st_size <= 1024


def test_absolute_caller_path_cannot_supply_a_fake_tool_after_snapshotting(
    tmp_path, monkeypatch
):
    caller = tmp_path / "caller" / "node_modules" / ".bin"
    caller.mkdir(parents=True)
    wrapper = caller / "repository-supplied-analyzer"
    wrapper.write_text("#!/bin/sh\necho unsafe\n")
    wrapper.chmod(0o755)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    monkeypatch.setenv("PATH", str(caller))
    assert run([wrapper.name], cwd=snapshot).status == "missing"
    monkeypatch.setenv("DIFF_GREMLIN_TOOL_PATH", str(caller))
    # An explicitly declared installed tool directory is a deliberate trust boundary.
    assert run([wrapper.name], cwd=snapshot).stdout == "unsafe\n"


def test_lexical_repo_executable_symlink_is_rejected(tmp_path):
    (tmp_path / "tool").symlink_to(shutil.which("git"))
    assert run([str(tmp_path / "tool")], cwd=tmp_path).status == "missing"


def test_symlinked_python_retains_its_virtual_environment(tmp_path):
    import venv

    environment = tmp_path / "tool-env"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    executable = environment / (
        "Scripts/python.exe" if os.name == "nt" else "bin/python"
    )
    result = run([str(executable), "-c", "import sys;print(sys.prefix)"])
    assert result.status == "ok" and result.returncode == 0
    assert Path(result.stdout.strip()) == environment


def test_data_output_preserves_blob_bytes_without_leaking_diagnostics(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "controlled-fake-sensitive-value")
    text = "https://user:controlled-fake-sensitive-value@example.invalid/file"
    code = "import sys;print(sys.argv[1]);print(sys.argv[1],file=sys.stderr)"
    result = run([sys.executable, "-c", code, text], data_output=True)
    assert result.stdout == text + "\n"
    assert "controlled-fake-sensitive-value" not in result.stderr + repr(result.args)


def test_declared_tool_directory_precedes_system_fallback(tmp_path, monkeypatch):
    tools = tmp_path / "tools"
    tools.mkdir()
    binary = tools / "git"
    binary.write_text("#!/bin/sh\necho declared-fixture-tool\n")
    binary.chmod(0o755)
    monkeypatch.setenv("DIFF_GREMLIN_TOOL_PATH", str(tools))
    assert run(["git", "--version"]).stdout == "declared-fixture-tool\n"
