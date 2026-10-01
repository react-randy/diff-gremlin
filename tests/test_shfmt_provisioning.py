"""Checksum-first standalone shfmt provisioning and failure controls."""

import hashlib
import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "provision_shfmt", _ROOT / "scripts" / "provision_shfmt.py"
)
assert _SPEC is not None and _SPEC.loader is not None
helper = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(helper)


def verified_inputs(monkeypatch):
    """Replace network data with independent digests rather than bypassing verification."""
    executable, license_text = (
        b"verified executable fixture",
        b"verified license fixture",
    )
    monkeypatch.setattr(helper, "artifact_name", lambda: "linux_amd64")
    monkeypatch.setitem(
        helper.ARTIFACTS, "linux_amd64", hashlib.sha256(executable).hexdigest()
    )
    monkeypatch.setattr(
        helper, "LICENSE_SHA256", hashlib.sha256(license_text).hexdigest()
    )
    calls = []

    def download(url, limit):
        calls.append((url, limit))
        return license_text if url.endswith("/LICENSE") else executable

    monkeypatch.setattr(helper, "download", download)
    return executable, license_text, calls


@pytest.mark.parametrize(
    "system,machine,expected",
    [
        ("Linux", "x86_64", "linux_amd64"),
        ("Linux", "aarch64", "linux_arm64"),
        ("Darwin", "AMD64", "darwin_amd64"),
        ("Darwin", "arm64", "darwin_arm64"),
    ],
)
def test_reviewed_platform_mapping(monkeypatch, system, machine, expected):
    monkeypatch.setattr(helper.platform, "system", lambda: system)
    monkeypatch.setattr(helper.platform, "machine", lambda: machine)
    assert helper.artifact_name() == expected


def test_unsupported_platform_fails_before_download(monkeypatch, tmp_path):
    monkeypatch.setattr(helper.platform, "system", lambda: "Windows")
    with (
        patch.object(helper, "download") as download,
        pytest.raises(ValueError, match="support"),
    ):
        helper.provision(tmp_path / "bin")
    download.assert_not_called()
    assert not (tmp_path / "bin").exists()


def test_exact_reviewed_hash_manifest_and_license_asset():
    assert helper.ARTIFACTS == {
        "linux_amd64": "76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf",
        "linux_arm64": "5f2db09dae91fca848f7adbdd014632e921a383863a2ad7e0450ad3aba0c6489",
        "darwin_amd64": "d33eee0da0f92835b3562e9767a05cee7e4eaeef47daa03bfd09da17b4b590a6",
        "darwin_arm64": "b7c872db63553ccffc7253aba3ed7d4885a27d83f1ba567b1138c6315a5847e5",
    }
    license_text = (
        _ROOT / "src/diff_gremlin/analyzers/shell/assets/SHFMT-LICENSE"
    ).read_bytes()
    assert hashlib.sha256(license_text).hexdigest() == helper.LICENSE_SHA256
    assert b"Daniel" in license_text and b"Redistribution" in license_text


@pytest.mark.parametrize("bad_part", ["executable", "license"])
def test_bad_hash_preserves_existing_install(monkeypatch, tmp_path, bad_part):
    verified_inputs(monkeypatch)
    if bad_part == "executable":
        monkeypatch.setitem(helper.ARTIFACTS, "linux_amd64", "0" * 64)
    else:
        monkeypatch.setattr(helper, "LICENSE_SHA256", "0" * 64)
    (tmp_path / "shfmt").write_bytes(b"old executable")
    (tmp_path / "SHFMT-LICENSE").write_bytes(b"old license")
    with pytest.raises(ValueError, match="checksum"):
        helper.provision(tmp_path)
    assert (tmp_path / "shfmt").read_bytes() == b"old executable"
    assert (tmp_path / "SHFMT-LICENSE").read_bytes() == b"old license"
    assert len(list(tmp_path.iterdir())) == 2


def test_both_assets_verified_before_executable_write(monkeypatch, tmp_path):
    executable, license_text, calls = verified_inputs(monkeypatch)
    destination = tmp_path / "bin"
    helper.provision(destination)
    assert (destination / "shfmt").read_bytes() == executable
    assert (destination / "shfmt").stat().st_mode & 0o777 == 0o755
    assert (destination / "SHFMT-LICENSE").read_bytes() == license_text
    assert (
        helper.COMMIT in calls[1][0]
        and "v3.14.1/shfmt_v3.14.1_linux_amd64" in calls[0][0]
    )
    assert calls[0][1] == 8 * 1024 * 1024 and calls[1][1] == 64 * 1024
    assert not list(destination.glob(".shfmt-*"))


def test_download_uses_shared_supervised_boundary(monkeypatch):
    calls = []

    class Transfer:
        @staticmethod
        def download(url, limit):
            calls.append((url, limit))
            return b"bounded fixture"

    monkeypatch.setattr(helper, "transfer_helper", lambda: Transfer)
    assert helper.download("https://github.com/official", 10) == b"bounded fixture"
    assert calls == [("https://github.com/official", 10)]


def test_partial_publication_error_keeps_old_binary_and_cleans_staging(
    monkeypatch, tmp_path
):
    verified_inputs(monkeypatch)
    (tmp_path / "shfmt").write_bytes(b"old executable")
    original_replace = Path.replace

    def replace_file(path, destination):
        if Path(destination).name == "shfmt":
            raise OSError("synthetic publication failure")
        return original_replace(path, destination)

    monkeypatch.setattr(Path, "replace", replace_file)
    with pytest.raises(
        OSError, match="license published; executable publication incomplete"
    ):
        helper.provision(tmp_path)
    assert (tmp_path / "shfmt").read_bytes() == b"old executable"
    assert not list(tmp_path.glob(".shfmt-*"))


def test_staging_interruption_cleans_file(monkeypatch, tmp_path):
    def fail_mode(*args):
        raise KeyboardInterrupt()

    monkeypatch.setattr(Path, "chmod", fail_mode)
    with pytest.raises(KeyboardInterrupt):
        helper.prepared_file(tmp_path, b"verified bytes", 0o755)
    assert not list(tmp_path.iterdir())


def test_provisioner_is_standalone():
    import ast

    tree = ast.parse((_ROOT / "scripts/provision_shfmt.py").read_text())
    modules = [
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    ]
    modules.extend(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    assert not any(module.startswith("diff_gremlin") for module in modules)
