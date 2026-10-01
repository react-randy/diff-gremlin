"""Content scope, snapshot parity, bounded omissions, and security controls."""

import os
import random
import shutil
import subprocess

import pytest

from diff_gremlin import inventory
from diff_gremlin.acquisition import objects, repositories, working
from diff_gremlin.acquisition.snapshots import acquire_comparison, acquire_source
from diff_gremlin.analyzers.secrets import _analyze_patterns, analyze_secrets
from diff_gremlin.analyzers.unicode import _control_rule, analyze_unicode
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.sources import ReviewTarget, SourceScopeEntry
from diff_gremlin.process import run, trusted_path
from diff_gremlin.source_scope import classify_content


def git(root, *args):
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=root,
        env={
            "PATH": os.defpath,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        },
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def context(root, scratch, scope_manifest=()):
    selected = inventory.collect_inventory(root, scope_manifest)
    scratch.mkdir(exist_ok=True)
    return ScanContext(
        root,
        selected.files,
        selected.production_files,
        selected.languages,
        "full",
        30,
        scratch,
        run,
        selected.scope_manifest,
    )


@pytest.mark.parametrize(
    ("path", "content", "expected"),
    [
        ("asset.jar", b"PK\x03\x04\x00\xff", "binary-asset"),
        ("asset.png", b"\x89PNG\r\n\x1a\n\x00", "binary-asset"),
        ("code.py", b"PK\x03\x04\x00\xff", "possible-source"),
        ("asset.jar", b"password = source_is_still_text", "text"),
        ("asset.png", b"const code = 1;", "text"),
        ("asset.dat", b"\x00\xff", "possible-source"),
        ("readme.md", b"bad\xff", "possible-source"),
        ("empty", b"", "text"),
    ],
)
def test_content_evidence_does_not_trust_suffix(path, content, expected):
    assert classify_content(path, content)[0] == expected


@pytest.fixture
def repository(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture@example.test")
    (root / "asset.jar").write_bytes(b"PK\x03\x04\x00\xff" + b"x" * 4096)
    (root / "main.py").write_text("answer = 1\n")
    git(root, "add", ".")
    git(root, "commit", "-m", "fixture")
    monkeypatch.setattr(objects, "MAX_FILE_BYTES", 128)
    monkeypatch.setattr(working, "MAX_FILE_BYTES", 128)
    return root, git(root, "rev-parse", "HEAD")


def test_local_ref_working_remote_and_review_side_parity(repository, monkeypatch):
    root, commit = repository
    with acquire_source(str(root), ref=commit) as immutable:
        expected = immutable.scope_manifest
        assert not (immutable.root / "asset.jar").exists()
        assert expected[0].classification == "binary-asset"
        assert expected[0].size_bytes > objects.MAX_FILE_BYTES
        assert (
            inventory.collect_inventory(immutable.root, expected).stage.status == "ok"
        )
    with acquire_source(str(root)) as working_snapshot:
        assert working_snapshot.scope_manifest == expected
        assert not working_snapshot.identity.dirty
    review = ReviewTarget(
        "github",
        "https://github.com/team/repo/pull/1",
        "team/repo",
        1,
        str(root),
        str(root),
        commit,
        commit,
    )
    with acquire_comparison(str(root), commit, commit, review=review) as pair:
        assert pair.base.scope_manifest == pair.head.scope_manifest == expected
        assert pair.base.identity.commit_sha == pair.head.identity.commit_sha == commit

    def fetch(_git, destination, _url, _ref):
        shutil.copytree(
            root / ".git/objects", destination / "objects", dirs_exist_ok=True
        )
        (destination / "FETCH_HEAD").write_text(commit + "\n")

    monkeypatch.setattr(repositories, "_fetch", fetch)
    with acquire_source("https://github.com/team/repo.git", ref=commit) as remote:
        assert remote.scope_manifest == expected
        assert remote.identity.commit_sha == commit


def test_omitted_asset_dirty_identity_hashes_beyond_probe(repository):
    root, _ = repository
    with (root / "asset.jar").open("ab") as stream:
        stream.write(b"changed after classification sample")
    with acquire_source(str(root)) as snapshot:
        assert snapshot.identity.dirty
        assert snapshot.scope_manifest[0].classification == "binary-asset"


def test_oversized_possible_source_has_manifest_and_security_gap(repository, tmp_path):
    root, _ = repository
    (root / "large.py").write_text("x = 1\n" * 100)
    for ref in (None, "HEAD"):
        if ref:
            git(root, "add", "large.py")
            git(root, "commit", "-m", "large source")
        with acquire_source(str(root), ref=ref) as snapshot:
            selected = inventory.collect_inventory(
                snapshot.root, snapshot.scope_manifest
            )
            assert selected.stage.status == "limited"
            assert selected.stage.metrics["omitted_possible_source_files"] == 1
            ctx = context(snapshot.root, tmp_path / "scratch", snapshot.scope_manifest)
            result = analyze_unicode(ctx)
            assert result.status == "limited"
            assert result.metrics["skipped_paths"] == ["large.py"]
            assert result.eligible_files == result.analyzed_files + 1


def test_read_budget_gap_never_claims_clean(repository, monkeypatch):
    root, _ = repository
    monkeypatch.setattr(working, "MAX_TREE_BYTES", 1)
    with acquire_source(str(root)) as snapshot:
        assert snapshot.identity.dirty
        assert all(
            row.classification == "possible-source" for row in snapshot.scope_manifest
        )
        assert (
            inventory.collect_inventory(
                snapshot.root, snapshot.scope_manifest
            ).stage.status
            == "limited"
        )


def test_git_aggregate_budget_returns_explicit_partial(repository, monkeypatch):
    root, commit = repository
    monkeypatch.setattr(objects, "MAX_TREE_BYTES", 32)
    with acquire_source(str(root), ref=commit) as snapshot:
        assert (snapshot.root / "main.py").exists()
        assert snapshot.scope_manifest[0].classification == "possible-source"
        assert (
            inventory.collect_inventory(
                snapshot.root, snapshot.scope_manifest
            ).stage.status
            == "limited"
        )


def test_safe_links_are_inert_and_visible(repository):
    root, _commit = repository
    (root / "linked.py").symlink_to("main.py")
    git(root, "add", "linked.py")
    git(root, "commit", "-m", "inert link")
    for ref in (None, "HEAD"):
        with acquire_source(str(root), ref=ref) as snapshot:
            assert (snapshot.root / "linked.py").is_symlink()
            selected = inventory.collect_inventory(
                snapshot.root, snapshot.scope_manifest
            )
            assert selected.stage.status == "limited"
            assert any(
                row.relative_path == "linked.py" for row in selected.scope_manifest
            )
    (root / "escape").symlink_to("../../private")
    with pytest.raises(RuntimeError, match="escapes"), acquire_source(str(root)):
        pass


def test_fake_asset_suffix_still_receives_secret_and_unicode_analysis(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    token = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6"
    (root / "text.png").write_text(token + "\n\u202e")
    (root / "archive.jar").write_bytes(b"PK\x03\x04\x00\xff")
    ctx = context(root, tmp_path / "scratch")
    assert len(ctx.files) == 1
    assert _analyze_patterns(ctx).metrics["match_count"] == 1
    unicode = analyze_unicode(ctx)
    assert unicode.status == "ok" and len(unicode.findings) == 1
    assert unicode.findings[0].path == "text.png"


def test_unicode_candidate_search_matches_exhaustive_contextual_reference(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    candidates = "".join(
        chr(code)
        for code in [
            0xAD,
            0x61C,
            0x180E,
            *range(0x200B, 0x2010),
            *range(0x202A, 0x202F),
            *range(0x2060, 0x206A),
            0xFEFF,
            *range(0xFE00, 0xFE10),
            *range(0xE0001, 0xE0080),
            *range(0xE0100, 0xE01F0),
        ]
    )
    rng = random.Random(47)
    alphabet = candidates + "\nASCII漢字ع👩👨❤"
    text = "\ufeff漢\u200d字👩\u200d👨a\u200dZ\n" + "".join(
        rng.choices(alphabet, k=6000)
    )
    (root / "text.txt").write_text(text)
    expected = []
    line, column = 1, 1
    for index, char in enumerate(text):
        rule = _control_rule(text, index)
        if rule:
            expected.append((rule[0], rule[1], line, column, f"U+{ord(char):04X}"))
        if char == "\n":
            line, column = line + 1, 1
        else:
            column += 1
    result = analyze_unicode(context(root, tmp_path / "scratch"))
    assert [
        (f.rule, f.severity, f.line, f.column, f.symbol) for f in result.findings
    ] == expected


@pytest.mark.parametrize("size", [1200000, inventory.MAX_FILE_BYTES])
def test_native_gitleaks_scans_text_above_old_one_megabyte_limit(tmp_path, size):
    if not shutil.which("gitleaks", path=trusted_path()):
        pytest.skip("Native installed Gitleaks required")
    root = tmp_path / "root"
    root.mkdir()
    token = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6"
    suffix = "\n" + token + "\n"
    (root / "text.jar").write_text("x" * (size - len(suffix)) + suffix)
    result = analyze_secrets(context(root, tmp_path / "scratch"))
    assert result.tool == "gitleaks" and result.status == "ok", result.reason
    assert result.analyzed_files == 1 and result.metrics["match_count"] >= 1
    assert token not in repr(result)


def test_declared_possible_source_stays_visible_in_security(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "readme").write_text("ordinary")
    scope = (SourceScopeEntry("unread.py", 200, "possible-source", "unreadable"),)
    ctx = context(root, tmp_path / "scratch", scope)
    for analyzer in (analyze_unicode, _analyze_patterns):
        result = analyzer(ctx)
        assert result.status == "limited"
        assert result.metrics["skipped_paths"] == ["unread.py"]
        assert result.eligible_files == 2


def test_unknown_binary_source_is_retained_as_limitation(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "code.py").write_bytes(b"PK\x03\x04\x00\xff")
    (root / "unknown.bin").write_bytes(b"unknown\x00")
    selected = inventory.collect_inventory(root)
    assert selected.stage.status == "limited"
    assert len(selected.files) == 2
    assert all(file.classification == "possible-source" for file in selected.files)
    result = analyze_unicode(context(root, tmp_path / "scratch"))
    assert result.status == "limited" and result.analyzed_files == 0
    assert result.eligible_files == 2


@pytest.mark.parametrize(
    "content",
    [
        b"RIFF\x04\x00\x00\x00WEBP",
        b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isomiso2",
        b"%PDF-1.7\n\xff",
    ],
)
def test_media_headers_define_asset_scope_with_content_evidence(content):
    assert classify_content("asset", content)[0] == "binary-asset"
    assert classify_content("code.ts", content)[0] == "possible-source"


def test_malformed_media_header_does_not_certify_asset():
    assert (
        classify_content("asset.mp4", b"\x00\x00\x00\xffftypisom\x00\x00\x00\x00")[0]
        == "possible-source"
    )
    assert (
        classify_content("asset.webp", b"RIFF\x00\x00\x00\x00TEXT")[0]
        == "possible-source"
    )


def test_security_actual_size_guard_catches_growth(tmp_path, monkeypatch):
    from diff_gremlin import text_content

    root = tmp_path / "root"
    root.mkdir()
    path = root / "source.py"
    path.write_text("initial")
    ctx = context(root, tmp_path / "scratch")
    monkeypatch.setattr(text_content, "MAX_FILE_BYTES", 16)
    path.write_text("x" * 17)
    for analyzer in (_analyze_patterns, analyze_unicode):
        result = analyzer(ctx)
        assert result.status == "limited"
        assert result.metrics["skipped_paths"] == ["source.py"]
        assert result.analyzed_files == 0


def test_inventory_entry_cap_has_canonical_manifest(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("a")
    (tmp_path / "b.py").write_text("b")
    monkeypatch.setattr(inventory, "MAX_ENTRIES", 1)
    selected = inventory.collect_inventory(tmp_path)
    assert selected.stage.status == "limited"
    assert selected.stage.metrics["scope_manifest"][0]["relative_path"] == "b.py"
    assert selected.stage.metrics["omitted_possible_source_files"] == 1


def test_unreadable_working_source_has_visible_partial_manifest(
    repository, monkeypatch
):
    from diff_gremlin.acquisition import working_capture

    root, _ = repository
    original = working_capture.os.open

    def unreadable(path, *args, **kwargs):
        if path == "main.py":
            raise PermissionError("controlled private context")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(working_capture.os, "open", unreadable)
    with acquire_source(str(root)) as snapshot:
        assert snapshot.identity.dirty
        selected = inventory.collect_inventory(snapshot.root, snapshot.scope_manifest)
        assert selected.stage.status == "limited"
        assert any(row.relative_path == "main.py" for row in snapshot.scope_manifest)
        assert "controlled private context" not in repr(snapshot.scope_manifest)
