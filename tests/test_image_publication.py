"""Reject stale releases, ambiguous registry failures and substituted image receipts."""

import base64
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from scripts.image_publication_support import (
    identity,
    policy,
    receipts,
    registry,
    transport,
)

ROOT = Path(__file__).parents[1]
SOURCE = "a" * 40
DIGESTS = {"amd64": "sha256:" + "1" * 64, "arm64": "sha256:" + "2" * 64}


@pytest.fixture
def context():
    return {
        "GITHUB_REPOSITORY": policy.REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(policy.REPOSITORY_ID),
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": SOURCE,
    }


@pytest.fixture
def release():
    return {
        "id": 123,
        "tag_name": "v1.0.3",
        "draft": False,
        "prerelease": False,
        "published_at": "2026-10-01T00:00:00Z",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("full_name", "another/repository"),
        ("id", 1),
        ("private", True),
        ("default_branch", "develop"),
    ],
)
def test_publication_rejects_repository_substitution(context, field, value):
    repository = {
        "full_name": policy.REPOSITORY,
        "id": policy.REPOSITORY_ID,
        "private": False,
        "default_branch": "main",
    }
    identity.validate_repository(context, repository)
    repository[field] = value
    with pytest.raises(ValueError):
        identity.validate_repository(context, repository)


@pytest.mark.parametrize(
    "field,value",
    [
        ("GITHUB_REPOSITORY", "someone/diff-gremlin"),
        ("GITHUB_REPOSITORY_ID", "2"),
    ],
)
def test_fork_cannot_publish(context, field, value):
    context[field] = value
    with pytest.raises(ValueError):
        identity.validate_repository(context, {})


@pytest.mark.parametrize(
    "field,value",
    [
        ("tag_name", "v1.0.0"),
        ("draft", True),
        ("prerelease", True),
        ("published_at", None),
        ("id", True),
    ],
)
def test_unpublished_or_different_release_cannot_publish(release, field, value):
    identity.validate_release(release)
    release[field] = value
    with pytest.raises(ValueError):
        identity.validate_release(release)


def test_dispatch_requires_main_and_fixed_tag(context, release):
    event = {"inputs": {"tag": "v1.0.3"}}
    identity.validate_event(context, event, release)
    context["GITHUB_REF"] = "refs/heads/unreviewed"
    with pytest.raises(ValueError, match="from main"):
        identity.validate_event(context, event, release)
    context["GITHUB_REF"] = "refs/heads/main"
    event["inputs"]["tag"] = "v1.0.3; touch should-not-run"
    with pytest.raises(ValueError, match=r"name v1\.0\.3"):
        identity.validate_event(context, event, release)


def test_release_event_requires_current_published_identity(context, release):
    context.update(GITHUB_EVENT_NAME="release", GITHUB_REF="refs/tags/v1.0.3")
    event = {"action": "published", "release": dict(release)}
    identity.validate_event(context, event, release)
    event["release"]["id"] += 1
    with pytest.raises(ValueError, match="identity has changed"):
        identity.validate_event(context, event, release)
    event["release"]["id"] = release["id"]
    event["action"] = "edited"
    with pytest.raises(ValueError, match="must be published"):
        identity.validate_event(context, event, release)


@pytest.mark.parametrize("event_name", ["pull_request", "push", "pull_request_target"])
def test_untrusted_event_cannot_publish(context, release, event_name):
    context["GITHUB_EVENT_NAME"] = event_name
    with pytest.raises(ValueError, match="Unsupported"):
        identity.validate_event(context, {}, release)


@pytest.mark.parametrize(
    "tag,main,checkout,expected",
    [
        (SOURCE, "b" * 40, SOURCE, None),
        (SOURCE, SOURCE, "b" * 40, None),
        (SOURCE, SOURCE, SOURCE, "b" * 40),
        ("a" * 7, SOURCE, SOURCE, None),
    ],
)
def test_moving_or_nonimmutable_source_cannot_publish(
    context, tag, main, checkout, expected
):
    context["GITHUB_SHA"] = checkout
    with pytest.raises(ValueError):
        identity.validate_source(context, tag, main, expected)


def test_matching_full_source_identity_is_accepted(context):
    assert identity.validate_source(context, SOURCE, SOURCE, SOURCE) == SOURCE


@pytest.mark.parametrize("code", ["MANIFEST_UNKNOWN", "NAME_UNKNOWN"])
def test_explicit_authenticated_missing_manifest_is_accepted(code):
    registry.validate_absence(404, {"errors": [{"code": code}]})


@pytest.mark.parametrize(
    "status,body",
    [
        (200, {}),
        (401, {"errors": [{"code": "UNAUTHORIZED"}]}),
        (403, {}),
        (429, {}),
        (500, {}),
        (404, {}),
        (404, {"errors": []}),
        (404, {"errors": [{"code": "DENIED"}]}),
        (404, {"errors": [{"code": "MANIFEST_UNKNOWN"}, {"code": "DENIED"}]}),
    ],
)
def test_existing_tag_auth_failure_or_outage_never_proves_absence(status, body):
    with pytest.raises(ValueError):
        registry.validate_absence(status, body)


def create_receipts(tmp_path):
    for architecture, digest in DIGESTS.items():
        path = tmp_path / architecture / "receipt.json"
        path.parent.mkdir()
        data = receipts.receipt_identity(architecture, SOURCE, "42", "1")
        data["digest"] = digest
        path.write_text(json.dumps(data))
    return tmp_path


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "b" * 40),
        ("run_id", "43"),
        ("attempt", "2"),
        ("image", "ghcr.io/another/image"),
        ("version", "latest"),
        ("architecture", "arm64"),
        ("digest", "sha256:123"),
        ("unexpected", "value"),
    ],
)
def test_final_index_rejects_substituted_receipt(tmp_path, field, value):
    create_receipts(tmp_path)
    path = tmp_path / "amd64/receipt.json"
    receipt = json.loads(path.read_text())
    receipt[field] = value
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError):
        receipts.read_receipts(tmp_path, SOURCE, "42", "1")


def test_final_index_requires_both_native_proofs(tmp_path):
    create_receipts(tmp_path)
    assert receipts.read_receipts(tmp_path, SOURCE, "42", "1") == DIGESTS
    (tmp_path / "arm64/receipt.json").unlink()
    with pytest.raises(ValueError, match="exactly two"):
        receipts.read_receipts(tmp_path, SOURCE, "42", "1")


@pytest.mark.parametrize(
    "references,platform",
    [
        ([], "linux/amd64"),
        ([f"{policy.IMAGE}@{DIGESTS['amd64']}"] * 2, "linux/amd64"),
        (["ghcr.io/other/image@" + DIGESTS["amd64"]], "linux/amd64"),
        ([f"{policy.IMAGE}@sha256:short"], "linux/amd64"),
        ([f"{policy.IMAGE}@{DIGESTS['amd64']}"], "linux/arm64"),
    ],
)
def test_pushed_receipt_requires_correct_platform_and_unambiguous_digest(
    references, platform
):
    with pytest.raises(ValueError):
        receipts.pushed_receipt("amd64", SOURCE, "42", "1", platform, references)


def test_published_index_must_match_exact_native_digests():
    manifest = {
        "mediaType": policy.MANIFEST_TYPES[0],
        "manifests": [
            {"digest": value, "platform": {"os": "linux", "architecture": architecture}}
            for architecture, value in DIGESTS.items()
        ],
    }
    receipts.validate_index(manifest, DIGESTS)
    manifest["manifests"][0]["digest"] = "sha256:" + "3" * 64
    with pytest.raises(ValueError, match="does not match"):
        receipts.validate_index(manifest, DIGESTS)


@pytest.mark.parametrize(
    "architecture", ["386", "$(touch sentinel)", "amd64\nversion=latest"]
)
def test_receipt_rejects_unowned_architecture(architecture):
    with pytest.raises(ValueError):
        receipts.receipt_identity(architecture, SOURCE, "42", "1")


def test_registry_credentials_stay_in_headers(tmp_path, monkeypatch, capsys):
    login = base64.b64encode(b"FAKE_LOGIN_SECRET").decode()
    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "auths": {"ghcr.io": {"auth": login}},
            }
        )
    )
    calls = []

    def http_json(url, headers):
        calls.append((url, headers))
        if "/token?" in url:
            return 200, {"token": "FAKE_SCOPED_SECRET"}
        return 404, {"errors": [{"code": "MANIFEST_UNKNOWN"}]}

    monkeypatch.setattr(transport, "http_json", http_json)
    registry.require_absent(tmp_path)
    output = capsys.readouterr()
    assert "FAKE" not in output.out + output.err
    assert all("FAKE" not in url for url, _ in calls)
    assert calls[0][1]["Authorization"] == f"Basic {login}"
    assert calls[1][1]["Authorization"] == "Bearer FAKE_SCOPED_SECRET"


def test_guard_resolves_live_identity_and_writes_only_fixed_outputs(
    tmp_path, monkeypatch, context, release
):
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps({"inputs": {"tag": "v1.0.3"}}))
    output_path = tmp_path / "output"
    for key, value in context.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    metadata = {
        "": {
            "full_name": policy.REPOSITORY,
            "id": policy.REPOSITORY_ID,
            "private": False,
            "default_branch": "main",
        },
        "releases/tags/v1.0.3": release,
        "commits/v1.0.3": {"sha": SOURCE},
        "commits/main": {"sha": SOURCE},
    }
    monkeypatch.setattr(identity, "github_metadata", metadata.__getitem__)
    identity.guard(SOURCE)
    assert output_path.read_text() == f"sha={SOURCE}\nversion=1.0.3\nrelease_id=123\n"
    with pytest.raises(ValueError, match="identity changed during run"):
        identity.guard(SOURCE, "124")


@pytest.mark.parametrize(
    "destination", ["https://other.example/token", "http://ghcr.io/token"]
)
def test_registry_credentials_cannot_follow_foreign_or_http_redirects(destination):
    request = urllib.request.Request(
        "https://ghcr.io/token", headers={"Authorization": "fake"}
    )
    with pytest.raises(urllib.error.URLError, match="outside its origin"):
        transport.PublicationRedirects().redirect_request(
            request, None, 302, "", {}, destination
        )


def test_malformed_registry_credentials_fail_without_disclosure(tmp_path):
    secret = "FAKE_LOGIN_SECRET\ninvalid"
    (tmp_path / "config.json").write_text(
        json.dumps({"auths": {"ghcr.io": {"auth": secret}}})
    )
    with pytest.raises(ValueError) as error:
        registry.registry_token(tmp_path)
    assert "FAKE" not in str(error.value)


def invoke_publication(arguments, data=None):
    return subprocess.run(
        [sys.executable, "-m", "scripts.image_publication", *arguments],
        cwd=ROOT,
        input=json.dumps(data) if data is not None else None,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )


def test_publication_module_preserves_cli_from_trusted_checkout():
    result = invoke_publication(["--help"])
    assert result.returncode == 0
    assert (
        "Check the fixed Diff Gremlin release and its container publication receipts."
        in result.stdout
    )
    assert "{guard,absent,receipt,sources,index}" in result.stdout


def test_public_cli_receipt_sources_and_index_cross_module_boundaries(tmp_path):
    common = ["--sha", SOURCE, "--run-id", "42", "--attempt", "1"]
    directory = tmp_path / "receipts"
    for architecture, value in DIGESTS.items():
        output = directory / architecture / "receipt.json"
        result = invoke_publication(
            [
                "receipt",
                *common,
                "--architecture",
                architecture,
                "--platform",
                f"linux/{architecture}",
                "--output",
                str(output),
            ],
            [f"{policy.IMAGE}@{value}"],
        )
        assert result.returncode == 0, result.stderr
        assert json.loads(output.read_text())["digest"] == value
    result = invoke_publication(["sources", *common, "--receipts", str(directory)])
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        f"{policy.IMAGE}@{value}" for value in DIGESTS.values()
    ]
    manifest = {
        "mediaType": policy.MANIFEST_TYPES[0],
        "manifests": [
            {"digest": value, "platform": {"os": "linux", "architecture": architecture}}
            for architecture, value in DIGESTS.items()
        ],
    }
    result = invoke_publication(
        ["index", *common, "--receipts", str(directory)],
        manifest,
    )
    assert result.returncode == 0, result.stderr
    assert (
        result.stdout.strip()
        == "Published index matches both validated native image receipts"
    )


def test_public_cli_does_not_write_invalid_platform_receipt(tmp_path):
    output = tmp_path / "receipt.json"
    result = invoke_publication(
        [
            "receipt",
            "--sha",
            SOURCE,
            "--run-id",
            "42",
            "--attempt",
            "1",
            "--architecture",
            "amd64",
            "--platform",
            "linux/arm64",
            "--output",
            str(output),
        ],
        [f"{policy.IMAGE}@{DIGESTS['amd64']}"],
    )
    assert result.returncode == 1
    assert (
        "Image publication gate failed: Built image platform mismatch" in result.stderr
    )
    assert result.stdout == ""
    assert not output.exists()
