"""Snapshot regression controls prove nonmutation, immutability, and owned cleanup."""

import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from diff_gremlin.acquisition import (
    object_store,
    objects,
    repositories,
    working,
    working_reads,
)
from diff_gremlin.acquisition.auth import git_auth
from diff_gremlin.acquisition.git import Git
from diff_gremlin.acquisition.snapshots import acquire_comparison, acquire_source
from diff_gremlin.domain.sources import ReviewTarget


def git(repo, *args):
    env = {
        "PATH": os.defpath,
        "HOME": str(repo.parent),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=repo,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "caller repo"
    repo.mkdir()
    git(repo, "init", "-b", "main")
    git(repo, "config", "user.name", "Fixture")
    git(repo, "config", "user.email", "fixture@example.test")
    (repo / "code.py").write_text("original = 1\n")
    git(repo, "add", "code.py")
    git(repo, "commit", "-m", "base")
    base = git(repo, "rev-parse", "HEAD")
    (repo / "code.py").write_text("original = 2\n")
    git(repo, "commit", "-am", "head")
    return repo, base, git(repo, "rev-parse", "HEAD")


def fingerprint(root):
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def test_dirty_staged_unstaged_untracked_state_and_global_config_preserved(
    repository, tmp_path, monkeypatch
):
    repo, base, head = repository
    (repo / "code.py").write_text("staged = 3\n")
    git(repo, "add", "code.py")
    (repo / "code.py").write_text("unstaged = 4\n")
    (repo / "untracked.py").write_text("untracked = 5\n")
    global_config = tmp_path / "global-config"
    global_config.write_text("[safe]\n\tdirectory = /unchanged\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    before = fingerprint(repo)
    with acquire_source(str(repo)) as source:
        assert source.identity.dirty
        assert source.root != repo
        assert (source.root / "code.py").read_text() == "unstaged = 4\n"
        assert (source.root / "untracked.py").exists()
        assert not (source.root / ".git").exists()
        assert source.history_repo.is_dir()
        root = source.root.parent
    assert not root.exists()
    with acquire_comparison(str(repo), base, head) as pair:
        assert (pair.base.root / "code.py").read_text() == "original = 1\n"
        assert (pair.head.root / "code.py").read_text() == "original = 2\n"
        assert pair.comparison_base_sha == base
        assert pair.head.identity.commit_sha == head
        assert git(pair.base.history_repo, "rev-parse", "HEAD") == base
        assert git(pair.head.history_repo, "rev-parse", "HEAD") == head
    assert fingerprint(repo) == before
    assert global_config.read_text() == "[safe]\n\tdirectory = /unchanged\n"
    with pytest.raises(RuntimeError), acquire_comparison(str(repo), base, "absent-ref"):
        pytest.fail("bad ref must not produce a snapshot")
    assert fingerprint(repo) == before


def test_hostile_hooks_filters_fsmonitor_and_wrapper_never_execute(
    repository, tmp_path, monkeypatch
):
    repo, base, head = repository
    marker = tmp_path / "executed"
    command = f"echo unsafe > '{marker}'"
    (repo / ".git" / "hooks" / "post-checkout").write_text(f"#!/bin/sh\n{command}\n")
    (repo / ".git" / "hooks" / "post-checkout").chmod(0o755)
    git(repo, "config", "core.fsmonitor", command)
    git(repo, "config", "filter.hostile.clean", command)
    git(repo, "config", "filter.hostile.smudge", command)
    (repo / ".gitattributes").write_text("*.py filter=hostile\n")
    (repo / "git").write_text(f"#!/bin/sh\n{command}\n")
    (repo / "git").chmod(0o755)
    monkeypatch.setenv("PATH", f"{repo}:{os.environ['PATH']}")
    with acquire_source(str(repo)) as source:
        assert source.identity.dirty
    with acquire_comparison(str(repo), base, head):
        pass
    assert not marker.exists()


def test_ref_is_exact_even_when_working_tree_differs(repository):
    repo, base, _head = repository
    (repo / "code.py").write_text("different\n")
    with acquire_source(str(repo), ref=base) as source:
        assert source.identity.mode == "commit"
        assert source.identity.commit_sha == base
        assert not source.identity.dirty
        assert (source.root / "code.py").read_text() == "original = 1\n"


def test_source_blobs_preserve_nonutf8_and_secret_matching_bytes(
    repository, monkeypatch
):
    repo, _base, _head = repository
    token = "fake-source-token"
    monkeypatch.setenv("GH_TOKEN", token)
    content = token.encode() + b"\x00\xff\r\n"
    (repo / "binary.dat").write_bytes(content)
    git(repo, "add", "binary.dat")
    git(repo, "commit", "-m", "binary")
    with acquire_source(str(repo), ref="HEAD") as source:
        assert (source.root / "binary.dat").read_bytes() == content


def test_snapshot_cleanup_on_consumer_error_and_concurrent_independence(repository):
    repo, _base, _head = repository
    with (
        pytest.raises(RuntimeError, match="consumer"),
        acquire_source(str(repo)) as source,
    ):
        root = source.root.parent
        raise RuntimeError("consumer")
    assert not root.exists()

    def read():
        with acquire_source(str(repo)) as source:
            return source.root, (source.root / "code.py").read_text()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: read(), range(2)))
    assert results[0][0] != results[1][0]
    assert results[0][1] == results[1][1]
    assert all(not root.exists() for root, _ in results)


def test_external_symlinks_cannot_escape_and_internal_links_remain_inert(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "real.py").write_text("safe")
    (source / "safe.py").symlink_to("real.py")
    with acquire_source(str(source)) as snapshot:
        assert (snapshot.root / "safe.py").is_symlink()
        assert (snapshot.root / "safe.py").resolve().is_relative_to(snapshot.root)
    (source / "escape.py").symlink_to("../private.py")
    with pytest.raises(RuntimeError, match="escapes"), acquire_source(str(source)):
        pytest.fail("escaping symlink must fail")


def test_review_fork_same_name_and_moving_refs_use_captured_shas(repository, tmp_path):
    repo, base, _head = repository
    fork = tmp_path / "fork"
    shutil.copytree(repo, fork)
    (fork / "code.py").write_text("fork = 9\n")
    git(fork, "commit", "-am", "fork")
    fork_sha = git(fork, "rev-parse", "HEAD")
    review = ReviewTarget(
        "github",
        "https://github.com/team/repo/pull/1",
        "team/repo",
        1,
        str(repo),
        str(fork),
        base,
        fork_sha,
        "main",
        "main",
        "refs/pull/1/head",
    )
    (fork / "code.py").write_text("moving = 10\n")
    git(fork, "commit", "-am", "branch moved")
    with acquire_comparison(str(repo), "main", "main", review=review) as pair:
        assert pair.head.identity.commit_sha == fork_sha
        assert (pair.head.root / "code.py").read_text() == "fork = 9\n"
        assert pair.comparison_base_sha == base


def test_remote_wrong_object_rejected_and_no_secret_argv_or_remotes(
    repository, monkeypatch
):
    repo, base, head = repository
    calls = []

    def fake_fetch(git_client, destination, url, ref):
        calls.append((url, ref))
        shutil.copytree(
            repo / ".git" / "objects", destination / "objects", dirs_exist_ok=True
        )
        (destination / "FETCH_HEAD").write_text(head + "\n")

    monkeypatch.setattr(repositories, "_fetch", fake_fetch)
    review = ReviewTarget(
        "github",
        "https://github.com/team/repo/pull/1",
        "team/repo",
        1,
        "https://github.com/team/repo.git",
        "https://github.com/fork/repo.git",
        base,
        head,
    )
    with (
        pytest.raises(RuntimeError, match="captured provider SHA"),
        acquire_comparison("unused", base, head, review=review),
    ):
        pytest.fail("wrong immutable object must fail")
    assert calls == [(review.base_repo_url, base)]


def test_short_lived_exact_host_askpass_and_cleanup(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "fake-github-token")
    with git_auth("https://github.com/team/repo.git") as env:
        secret = Path(env["DIFF_GREMLIN_AUTH_FILE"])
        helper = Path(env["GIT_ASKPASS"])
        assert secret.stat().st_mode & 0o777 == 0o600
        child_env = {**env, "PATH": os.defpath}
        result = subprocess.run(
            [str(helper), "Password for 'https://oauth2@github.com':"],
            env=child_env,
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == "fake-github-token"
        denied = subprocess.run(
            [str(helper), "Password for 'https://attacker.test':"],
            env=child_env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert denied.returncode != 0 and not denied.stdout
        assert "fake-github-token" not in repr(env)
    assert not secret.exists() and not helper.exists()


def test_credential_urls_are_rejected_without_echo(tmp_path):
    with (
        pytest.raises(ValueError) as error,
        acquire_source("https://user:private-token@github.com/team/repo.git"),
    ):
        pass
    assert "private-token" not in str(error.value)


def test_ref_snapshot_rejects_tracked_escape_link(repository):
    repo, _base, _head = repository
    (repo / "escape").symlink_to("../../outside")
    git(repo, "add", "escape")
    git(repo, "commit", "-m", "unsafe link")
    with (
        pytest.raises(RuntimeError, match="escapes"),
        acquire_source(str(repo), ref="HEAD"),
    ):
        pytest.fail("tracked link must not escape")


def test_bare_and_unborn_repository_modes(repository, tmp_path):
    repo, _base, head = repository
    bare = tmp_path / "bare.git"
    git(repo, "clone", "--bare", str(repo), str(bare))
    with acquire_source(str(bare)) as source:
        assert source.identity.mode == "commit"
        assert source.identity.commit_sha == head
        assert (source.root / "code.py").exists()
        assert not (source.root / "objects").exists()
    unborn = tmp_path / "unborn"
    unborn.mkdir()
    git(unborn, "init")
    (unborn / "first.py").write_text("new")
    with acquire_source(str(unborn)) as source:
        assert source.identity.commit_sha == ""
        assert source.identity.dirty
        assert (source.root / "first.py").exists()


def test_local_comparison_never_fetches(repository, monkeypatch):
    repo, base, head = repository

    def forbidden(*args, **kwargs):
        pytest.fail("local comparison must not fetch")

    monkeypatch.setattr(repositories, "_fetch", forbidden)
    with acquire_comparison(str(repo), base, head):
        pass


def test_remote_success_is_object_only_without_persistent_remote_or_secret(
    repository, monkeypatch
):
    repo, _base, head = repository
    monkeypatch.setenv("GH_TOKEN", "fake-private-token")

    def fake_fetch(_git_client, destination, url, ref):
        assert "fake-private-token" not in url + ref
        shutil.copytree(
            repo / ".git" / "objects", destination / "objects", dirs_exist_ok=True
        )
        (destination / "FETCH_HEAD").write_text(head + "\n")

    monkeypatch.setattr(repositories, "_fetch", fake_fetch)
    with acquire_source("https://github.com/team/repo.git") as source:
        assert source.identity.commit_sha == head
        config = (source.history_repo / "config").read_text()
        assert "fake-private-token" not in config
        assert "remote" not in config
        assert git(source.history_repo, "rev-list", "--count", "HEAD") == "2"


@pytest.mark.parametrize(
    ("output", "message"),
    [
        (b"missing newline", "incomplete object header"),
        (b"wrong blob 3\nabc\n", "captured tree metadata"),
        (b"a blob 3\nab", "incomplete object body"),
        (b"a blob 3\nabc!", "incomplete object body"),
        (b"a blob 3\nabc\nextra", "unexpected trailing data"),
    ],
)
def test_blob_batches_reject_malformed_protocol(output, message, tmp_path, monkeypatch):
    client = Git(120)
    monkeypatch.setattr(client, "run", lambda *args, **kwargs: output.decode())
    entries = (objects.TreeEntry("code.py", "100644", "a", 3),)
    with pytest.raises(RuntimeError, match=message):
        list(objects._blob_batches(client, tmp_path, entries))


@pytest.mark.parametrize("limit", ["file", "tree", "entries"])
def test_working_copy_failure_preserves_source_bytes(limit, tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "code.py").write_bytes(b"captured bytes")
    if limit == "file":
        monkeypatch.setattr(working, "MAX_FILE_BYTES", 2)
    elif limit == "tree":
        monkeypatch.setattr(working, "MAX_TREE_BYTES", 2)
    elif limit == "entries":
        monkeypatch.setattr(working, "MAX_ENTRIES", 0)
    if limit == "entries":
        with (
            pytest.raises(RuntimeError, match="limits"),
            acquire_source(str(source)),
        ):
            pytest.fail("entry limit must prevent snapshot delivery")
    else:
        with acquire_source(str(source)) as snapshot:
            assert len(snapshot.scope_manifest) == 1
            omission = snapshot.scope_manifest[0]
            assert omission.relative_path == "code.py"
            assert omission.classification == "possible-source"
            assert not (snapshot.root / "code.py").exists()
    assert (source / "code.py").read_bytes() == b"captured bytes"


def test_working_copy_read_failure_retains_safe_error(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "code.py").write_text("safe")

    def denied(*args, **kwargs):
        raise PermissionError("private-path")

    monkeypatch.setattr(working_reads.os, "open", denied)
    with pytest.raises(RuntimeError, match="could not read a path safely") as error:
        working.copy_working_tree(source, tmp_path / "snapshot", deadline=float("inf"))
    assert isinstance(error.value.__cause__, PermissionError)
    assert "private-path" not in str(error.value)


@pytest.mark.parametrize("limit", ["bytes", "entries"])
def test_inert_history_copy_bounds_preserve_caller(repository, limit, monkeypatch):
    repo, _base, _head = repository
    before = fingerprint(repo)
    if limit == "bytes":
        monkeypatch.setattr(object_store, "MAX_HISTORY_BYTES", 0)
    elif limit == "entries":
        monkeypatch.setattr(object_store, "MAX_ENTRIES", 0)
    with (
        pytest.raises(RuntimeError, match="limits"),
        acquire_source(str(repo)),
    ):
        pytest.fail("history limit must prevent snapshot delivery")
    assert fingerprint(repo) == before


@pytest.mark.parametrize("copy", [working.copy_working_tree, objects.copy_object_store])
def test_filesystem_copy_expired_deadline_fails_before_source_write(copy, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "code.py").write_bytes(b"captured bytes")
    with pytest.raises(RuntimeError, match="deadline"):
        copy(source, tmp_path / "snapshot", deadline=0)
    assert (source / "code.py").read_bytes() == b"captured bytes"


def test_object_fifo_is_rejected_without_blocking_acquisition(tmp_path):
    source = tmp_path / "objects"
    source.mkdir()
    os.mkfifo(source / "object")
    code = (
        "import sys, time; from pathlib import Path; "
        "sys.path.insert(0, sys.argv[1]); "
        "from diff_gremlin.acquisition.objects import copy_object_store; "
        "copy_object_store(Path(sys.argv[2]), Path(sys.argv[3]), "
        "deadline=time.monotonic() + 0.25)"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            code,
            str(Path(__file__).resolve().parents[1] / "src"),
            str(source),
            str(tmp_path / "snapshot"),
        ],
        env={"PATH": os.defpath},
        timeout=2,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "Git object store contains a nonregular object" in result.stderr
    assert (source / "object").exists()
