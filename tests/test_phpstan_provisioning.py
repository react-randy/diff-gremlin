"""Standalone PHPStan provisioning rejects unreviewed assets before publication."""

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "provision_phpstan", ROOT / "scripts/provision_phpstan.py"
)
assert SPEC is not None and SPEC.loader is not None
helper = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(helper)


def reviewed_inputs(monkeypatch):
    """Use independently hashed byte fixtures through the real validation path."""
    inputs = {
        helper.PHAR_URL: b"verified phar fixture",
        helper.LICENSE_URL: b"verified MIT fixture",
        helper.PHP_LICENSE_URL: b"verified PHP license fixture",
    }
    for url, prefix in (
        (helper.PHAR_URL, "PHAR"),
        (helper.LICENSE_URL, "LICENSE"),
        (helper.PHP_LICENSE_URL, "PHP_LICENSE"),
    ):
        monkeypatch.setattr(helper, f"{prefix}_SIZE", len(inputs[url]))
        monkeypatch.setattr(
            helper, f"{prefix}_SHA256", hashlib.sha256(inputs[url]).hexdigest()
        )
    calls = []

    def download(url, limit):
        calls.append((url, limit))
        return inputs[url]

    monkeypatch.setattr(helper, "download", download)
    return inputs, calls


def test_exact_public_manifest_matches_provisioner_and_docker():
    manifest = json.loads((ROOT / "toolchain/php/manifest.json").read_text())
    phar = manifest["phpstan"]
    assert phar["version"] == helper.VERSION == "2.2.15"
    assert phar["sha256"] == helper.PHAR_SHA256
    assert phar["size"] == helper.PHAR_SIZE == 29_964_760
    assert phar["url"] == helper.PHAR_URL
    assert phar["commit"] == helper.COMMIT
    assert phar["license"]["sha256"] == helper.LICENSE_SHA256
    assert phar["license"]["url"] == helper.LICENSE_URL
    assert manifest["php"]["license"]["sha256"] == helper.PHP_LICENSE_SHA256
    assert manifest["php"]["license"]["url"] == helper.PHP_LICENSE_URL
    assert manifest["download_helper"]["sha256"] == helper.DOWNLOAD_HELPER_SHA256
    assert (
        hashlib.sha256((ROOT / "scripts/download_asset.py").read_bytes()).hexdigest()
        == helper.DOWNLOAD_HELPER_SHA256
    )
    docker = (ROOT / "Dockerfile").read_text()
    php = manifest["php"]
    assert f"FROM {php['image']}@{php['index_digest']} AS php" in docker
    assert "/opt/gremlin/php-bin" in docker
    assert "python -I /provision_phpstan.py /opt/gremlin/bin" in docker


@pytest.mark.parametrize("prefix", ["PHAR", "LICENSE", "PHP_LICENSE"])
@pytest.mark.parametrize("failure", ["size", "checksum"])
def test_invalid_asset_preserves_existing_install(
    monkeypatch, tmp_path, prefix, failure
):
    reviewed_inputs(monkeypatch)
    name = f"{prefix}_{'SIZE' if failure == 'size' else 'SHA256'}"
    monkeypatch.setattr(helper, name, 999 if failure == "size" else "0" * 64)
    for filename in ("phpstan.phar", "PHPSTAN-LICENSE", "PHP-LICENSE"):
        (tmp_path / filename).write_bytes(b"previous installed bytes")
    with pytest.raises(ValueError, match=failure):
        helper.provision(tmp_path)
    assert len(list(tmp_path.iterdir())) == 3
    assert all(
        p.read_bytes() == b"previous installed bytes" for p in tmp_path.iterdir()
    )


def test_verified_publication_modes_and_cleanup(monkeypatch, tmp_path):
    inputs, calls = reviewed_inputs(monkeypatch)
    destination = tmp_path / "bin"
    helper.provision(destination)
    for name, url, mode in (
        ("phpstan.phar", helper.PHAR_URL, 0o755),
        ("PHPSTAN-LICENSE", helper.LICENSE_URL, 0o644),
        ("PHP-LICENSE", helper.PHP_LICENSE_URL, 0o644),
    ):
        assert (destination / name).read_bytes() == inputs[url]
        assert (destination / name).stat().st_mode & 0o777 == mode
    assert calls == [(url, len(data)) for url, data in inputs.items()]
    assert not list(destination.glob(".phpstan-*"))


def test_transfer_failure_creates_no_installation(monkeypatch, tmp_path):
    with (
        patch.object(
            helper, "download", side_effect=ValueError("HTTPS transfer failed")
        ),
        pytest.raises(ValueError, match="HTTPS transfer"),
    ):
        helper.provision(tmp_path / "bin")
    assert not (tmp_path / "bin").exists()


def test_partial_publication_preserves_old_phar(monkeypatch, tmp_path):
    reviewed_inputs(monkeypatch)
    (tmp_path / "phpstan.phar").write_bytes(b"previous PHAR")
    replace = Path.replace

    def failed_phar(path, destination):
        if Path(destination).name == "phpstan.phar":
            raise OSError("synthetic publication failure")
        return replace(path, destination)

    monkeypatch.setattr(Path, "replace", failed_phar)
    with pytest.raises(OSError, match="published: PHPSTAN-LICENSE, PHP-LICENSE"):
        helper.provision(tmp_path)
    assert (tmp_path / "phpstan.phar").read_bytes() == b"previous PHAR"
    assert not list(tmp_path.glob(".phpstan-*"))


def test_staging_interruption_preserves_install(monkeypatch, tmp_path):
    reviewed_inputs(monkeypatch)
    (tmp_path / "phpstan.phar").write_bytes(b"previous PHAR")
    with (
        patch.object(Path, "chmod", side_effect=KeyboardInterrupt),
        pytest.raises(KeyboardInterrupt),
    ):
        helper.provision(tmp_path)
    assert (tmp_path / "phpstan.phar").read_bytes() == b"previous PHAR"
    assert not list(tmp_path.glob(".phpstan-*"))


def test_download_delegates_to_supervised_https_helper(monkeypatch):
    with patch.object(helper, "transfer_helper") as transfer:
        transfer.return_value.download.return_value = b"bounded bytes"
        assert helper.download(helper.PHAR_URL, 12) == b"bounded bytes"
        transfer.return_value.download.assert_called_once_with(helper.PHAR_URL, 12)


def test_helper_checksum_rejected_before_import(monkeypatch):
    monkeypatch.setattr(helper, "DOWNLOAD_HELPER_SHA256", "0" * 64)
    with (
        patch.object(helper.importlib.util, "spec_from_file_location") as importer,
        pytest.raises(ValueError, match="checksum mismatch"),
    ):
        helper.transfer_helper()
    importer.assert_not_called()


def test_unsupported_download_scheme_is_rejected_before_execution():
    with (
        patch("subprocess.run") as worker,
        pytest.raises(ValueError, match="requires HTTPS"),
    ):
        helper.download("http://github.com/unreviewed", 10)
    worker.assert_not_called()


def test_provisioner_never_executes_downloaded_code(monkeypatch, tmp_path):
    reviewed_inputs(monkeypatch)
    with patch("subprocess.run", side_effect=AssertionError("unexpected execution")):
        helper.provision(tmp_path)
    tree = ast.parse((ROOT / "scripts/provision_phpstan.py").read_text())
    imports = [
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    ]
    imports.extend(
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    )
    assert not any(name.startswith(("diff_gremlin", "subprocess")) for name in imports)
