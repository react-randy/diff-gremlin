"""Validate install failure boundaries and public release staging with owned fixtures."""

import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_unfinalized_installer_never_downloads(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "downloaded"
    curl = fake_bin / "curl"
    curl.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 99\n")
    curl.chmod(0o755)
    installer = tmp_path / "unfinalized-install.sh"
    installer.write_text(
        re.sub(
            r"(?m)^RELEASE_WHEEL_SHA256=.*$",
            "RELEASE_WHEEL_SHA256=REPLACE_WITH_FINAL_RELEASE_WHEEL_SHA256",
            (ROOT / "install.sh").read_text(),
        )
    )
    result = subprocess.run(
        ["sh", installer],
        env={**os.environ, "PATH": f"{fake_bin}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "not finalized" in result.stderr
    assert not marker.exists()


def installer_fixture(tmp_path, *, corrupt_wheel=False):
    assets = tmp_path / "assets"
    assets.mkdir()
    wheel = b"owned wheel verification fixture"
    wheel_name = "diff_gremlin-1.0.0-py3-none-any.whl"
    (assets / wheel_name).write_bytes(wheel + b"corrupt" if corrupt_wheel else wheel)
    (assets / "full-requirements.txt").write_text("# owned requirements fixture\n")
    provisioner = (
        "import pathlib,sys\npathlib.Path(sys.argv[1], 'gitleaks').write_text('fixture')\n"
    )
    (assets / "provision_gitleaks.py").write_text(provisioner)
    installer = (ROOT / "install.sh").read_text()
    installer = installer.replace(
        "REPLACE_WITH_FINAL_RELEASE_WHEEL_SHA256", hashlib.sha256(wheel).hexdigest()
    )
    for name, file in (
        ("FULL_LOCK_SHA256", "full-requirements.txt"),
        ("GITLEAKS_SCRIPT_SHA256", "provision_gitleaks.py"),
    ):
        installer = re.sub(
            rf"(?m)^{name}=.*$",
            f"{name}={hashlib.sha256((assets / file).read_bytes()).hexdigest()}",
            installer,
        )
    script = tmp_path / "install.sh"
    script.write_text(installer)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    tool = tmp_path / "tools"
    tool_bin = tmp_path / "tool-bin"
    trace = tmp_path / "trace.jsonl"
    curl = binaries / "curl"
    curl.write_text(
        f"#!{sys.executable}\nimport os,pathlib,sys\na=sys.argv\nout=pathlib.Path(a[a.index('--output')+1])\nsource=pathlib.Path(os.environ['FIXTURE_ASSETS'])/a[-1].rsplit('/',1)[-1]\nout.write_bytes(source.read_bytes())\n"
    )
    uv = binaries / "uv"
    uv.write_text(f"""#!{sys.executable}
import json,os,pathlib,sys
a=sys.argv[1:]
if a == ['--version']:
    print('uv 0.12.18'); raise SystemExit(0)
with open(os.environ['FIXTURE_TRACE'], 'a') as log:
    log.write(json.dumps(a)+'\\n')
if a[0] == '--no-config': a=a[1:]
if a[0] == 'venv':
    p=pathlib.Path(a[-1])/'bin'; p.mkdir(parents=True)
    (p/'python').symlink_to(sys.executable)
elif a[:2] == ['tool','install']:
    assert '--offline' in a and '--no-build' in a
    p=pathlib.Path(os.environ['UV_TOOL_DIR'])/'diff-gremlin'/'bin'; p.mkdir(parents=True)
    (p/'python').symlink_to(sys.executable)
    b=pathlib.Path(os.environ['UV_TOOL_BIN_DIR']); b.mkdir()
    entry=b/'diff-gremlin'; entry.write_text('#!/bin/sh\\necho "diff-gremlin 1.0.0"\\n'); entry.chmod(0o755)
elif a[:2] == ['tool','dir']:
    print(os.environ['UV_TOOL_BIN_DIR'] if '--bin' in a else os.environ['UV_TOOL_DIR'])
elif a[:2] == ['pip','install']:
    assert '--require-hashes' in a and '--only-binary' in a
else:
    raise AssertionError(a)
""")
    for binary in (curl, uv):
        binary.chmod(0o755)
    env = {
        **os.environ,
        "PATH": f"{binaries}:/usr/bin:/bin",
        "FIXTURE_ASSETS": str(assets),
        "FIXTURE_TRACE": str(trace),
        "UV_TOOL_DIR": str(tool),
        "UV_TOOL_BIN_DIR": str(tool_bin),
        "TMPDIR": str(tmp_path),
    }
    return script, env, tool, trace


def test_corrupt_download_never_installs_tool(tmp_path):
    script, env, tool, trace = installer_fixture(tmp_path, corrupt_wheel=True)
    result = subprocess.run(["sh", script], env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "checksum mismatch" in result.stderr
    assert not tool.exists()
    assert not trace.exists()
    assert not list(tmp_path.glob("diff-gremlin-install.*"))


def test_corrupt_provisioner_never_executes_or_installs_tool(tmp_path):
    script, env, tool, trace = installer_fixture(tmp_path)
    provisioner = Path(env["FIXTURE_ASSETS"]) / "provision_gitleaks.py"
    provisioner.write_text("raise RuntimeError('unverified code executed')\n")
    result = subprocess.run(["sh", script], env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 1
    assert "checksum mismatch" in result.stderr
    assert "unverified code executed" not in result.stderr
    assert not tool.exists()
    assert not trace.exists()
    assert not list(tmp_path.glob("diff-gremlin-install.*"))


def test_installer_uses_verified_wheels_before_offline_install(tmp_path):
    script, env, tool, trace = installer_fixture(tmp_path)
    result = subprocess.run(["sh", script], env=env, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    commands = [json.loads(line) for line in trace.read_text().splitlines()]
    pip_index = next(i for i, command in enumerate(commands) if command[1:3] == ["pip", "install"])
    install_index = next(
        i for i, command in enumerate(commands) if command[1:3] == ["tool", "install"]
    )
    assert pip_index < install_index
    assert "--offline" in commands[install_index]
    assert "--require-hashes" in commands[pip_index]
    assert (tool / "diff-gremlin/bin/gitleaks").read_text() == "fixture"
    assert "Uninstall:" in result.stdout
    assert not list(tmp_path.glob("diff-gremlin-install.*"))


def test_gitleaks_checksum_failure_cannot_write_binary(tmp_path, monkeypatch):
    provisioner = load_script("provision_gitleaks")
    monkeypatch.setattr(provisioner, "archive_name", lambda: "linux_x64")
    monkeypatch.setattr(provisioner, "download", lambda _: b"corrupt archive")
    target = tmp_path / "not-created"
    with pytest.raises(ValueError, match="checksum mismatch"):
        provisioner.provision(target)
    assert not target.exists()


def test_gitleaks_archive_links_are_rejected():
    provisioner = load_script("provision_gitleaks")
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as archive:
        member = tarfile.TarInfo("gitleaks")
        member.type = tarfile.SYMTYPE
        member.linkname = "../outside"
        archive.addfile(member)
    with (
        tarfile.open(fileobj=io.BytesIO(data.getvalue())) as archive,
        pytest.raises(ValueError, match="invalid"),
    ):
        provisioner.member_bytes(archive, "gitleaks")


def wheel_fixture(tmp_path, *, missing_asset=False):
    release = load_script("prepare_release")
    wheel = tmp_path / "diff_gremlin-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "diff_gremlin-1.0.0.dist-info/METADATA", "Name: diff-gremlin\nVersion: 1.0.0\n"
        )
        archive.writestr(
            "diff_gremlin-1.0.0.dist-info/entry_points.txt",
            "[console_scripts]\ndiff-gremlin = diff_gremlin.cli.main:main\n",
        )
        archive.writestr("diff_gremlin-1.0.0.dist-info/licenses/LICENSE", "MIT fixture")
        for name in release.ASSETS[:-1] if missing_asset else release.ASSETS:
            archive.writestr(name, "controlled nonempty asset")
    return release, wheel


def test_release_staging_requires_shipped_assets(tmp_path):
    release, wheel = wheel_fixture(tmp_path, missing_asset=True)
    destination = tmp_path / "release"
    with pytest.raises(KeyError):
        release.stage_release(wheel, destination)
    assert not destination.exists()


def test_release_staging_freezes_wheel_hash_without_changing_wheel(tmp_path):
    release, wheel = wheel_fixture(tmp_path)
    original = wheel.read_bytes()
    original_installer = (ROOT / "install.sh").read_bytes()
    destination = tmp_path / "release"
    release.stage_release(wheel, destination)
    assert wheel.read_bytes() == original
    assert (destination / wheel.name).read_bytes() == original
    assert (
        f"RELEASE_WHEEL_SHA256={release.digest(wheel)}" in (destination / "install.sh").read_text()
    )
    assert (ROOT / "install.sh").read_bytes() == original_installer
    for line in (destination / "SHA256SUMS").read_text().splitlines():
        checksum, name = line.split("  ")
        assert release.digest(destination / name) == checksum
    with pytest.raises(FileExistsError):
        release.stage_release(wheel, destination)
