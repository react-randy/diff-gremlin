"""Native delivery receipts and doctor discovery enforce distinct trust boundaries."""

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from diff_gremlin.acquisition.snapshots import acquire_source
from diff_gremlin.cli import doctor
from diff_gremlin.orchestration.scan import scan
from diff_gremlin.process import trusted_path
from diff_gremlin.reporting.serialization import report_document
from scripts import verify_docker


@pytest.fixture(scope="module")
def native_receipt(tmp_path_factory):
    root = tmp_path_factory.mktemp("delivery-source")
    verify_docker.write_control(root)
    with acquire_source(str(root)) as snapshot:
        receipt = report_document(scan(snapshot))
    assert receipt["assessment"]["complete"] is True
    return receipt


def test_native_mixed_language_receipt_passes_delivery_gate(native_receipt):
    checked = verify_docker.checked_stages(native_receipt, pinned_php=False)
    assert checked["security.execution"]["status"] == "ok"
    assert checked["shell.syntax.shfmt"]["status"] == "ok"


@pytest.mark.parametrize(
    "stage",
    ["security.execution", "inventory", "security.unicode", "python.deadcode.pyscn"],
)
@pytest.mark.parametrize("failure", ["failed", "absent"])
def test_delivery_rejects_missing_or_failed_selected_evidence(
    native_receipt, stage, failure
):
    receipt = copy.deepcopy(native_receipt)
    if failure == "absent":
        receipt["stages"] = [row for row in receipt["stages"] if row["id"] != stage]
    else:
        next(row for row in receipt["stages"] if row["id"] == stage)["status"] = failure
    with pytest.raises(ValueError, match="invalid bundled analyzer evidence"):
        verify_docker.checked_stages(receipt, pinned_php=False)


def test_delivery_rejects_incomplete_assessment(native_receipt):
    receipt = copy.deepcopy(native_receipt)
    receipt["assessment"]["complete"] = False
    with pytest.raises(ValueError, match="complete selected evidence"):
        verify_docker.checked_stages(receipt, pinned_php=False)


@pytest.mark.parametrize("exit_code", [1, 2, 3])
def test_positive_control_cannot_publish_after_nonzero_exit(
    monkeypatch, native_receipt, exit_code
):
    monkeypatch.setattr(
        verify_docker,
        "invoke",
        lambda *_: subprocess.CompletedProcess(
            [], exit_code, json.dumps(native_receipt), ""
        ),
    )
    with pytest.raises(ValueError, match="Docker control failed"):
        verify_docker.check_control("owned-image")


def test_doctor_sees_trusted_environment_without_relaxing_scan_target_exclusion(
    tmp_path, monkeypatch
):
    binaries = tmp_path / ".venv/bin"
    binaries.mkdir(parents=True)
    installed = Path(sys.executable).parent / "ruff"
    assert installed.is_file(), (
        "native doctor control requires the reviewed installed Ruff"
    )
    (binaries / "ruff").symlink_to(installed)
    monkeypatch.setattr(sys, "executable", str(binaries / "python"))
    monkeypatch.chdir(tmp_path)
    assert doctor.document()["tools"]["ruff"]["available"] is True
    assert str(binaries) not in trusted_path(tmp_path).split(":")
    assert shutil.which("ruff", path=trusted_path(tmp_path)) is None
