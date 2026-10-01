"""Own disposable snapshot lifetimes for repository and review analysis."""

import tempfile
from contextlib import contextmanager
from pathlib import Path

from diff_gremlin.acquisition.git import Git, remote_url
from diff_gremlin.acquisition.objects import extract_tree, tree_entries
from diff_gremlin.acquisition.repositories import (
    history_view,
    local_history,
    pin_history,
    remote_history,
    verify_sha,
)
from diff_gremlin.acquisition.working import copy_working_tree, working_tree_dirty
from diff_gremlin.domain.sources import (
    ReviewTarget,
    Snapshot,
    SnapshotPair,
    SourceIdentity,
)


def _local_path(target: str) -> Path:
    path = Path(target).expanduser().absolute()
    if path.is_symlink() or not path.is_dir():
        raise ValueError(
            "Local source must be an existing directory, not a symbolic link"
        )
    return path


def _identity(target: str, commit: str, date: str, mode: str, dirty: bool = False):
    return SourceIdentity(
        target,
        Path(target.rstrip("/")).name.removesuffix(".git"),
        commit,
        date,
        mode,
        dirty,
    )


def _ref_snapshot(
    git: Git, history: Path, commit: str, target: str, destination: Path
) -> Snapshot:
    pin_history(git, history, commit)
    extract_tree(git, history, commit, destination)
    return Snapshot(
        destination,
        _identity(target, commit, git.date(history, commit), "commit"),
        history,
    )


@contextmanager
def acquire_source(target: str, *, ref: str | None = None, timeout: float = 120.0):
    """Local defaults scan current files; an explicit ref scans only immutable objects."""
    git = Git(timeout)
    url = remote_url(target)
    with tempfile.TemporaryDirectory(prefix="diff-gremlin-source-") as directory:
        workspace = Path(directory)
        if url:
            history, commit = remote_history(
                git, url, ref or "HEAD", workspace / "history.git"
            )
            yield _ref_snapshot(git, history, commit, url, workspace / "source")
            return
        source = _local_path(target)
        bare = (source / "HEAD").is_file() and (source / "objects").is_dir()
        has_git = (source / ".git").exists() or bare
        if ref and not has_git:
            raise ValueError("An explicit ref requires a local Git repository")
        if has_git:
            history = local_history(git, source, workspace / "history.git")
            commits = git.run(
                ["rev-list", "--all", "--max-count=1"], cwd=source
            ).strip()
            commit = (
                git.resolve(source, ref or "HEAD") if commits or ref or bare else ""
            )
            if ref or bare:
                yield _ref_snapshot(
                    git, history, commit, str(source), workspace / "source"
                )
                return
        else:
            history, commit = None, ""
        copied = copy_working_tree(source, workspace / "source", deadline=git.deadline)
        dirty = bool(copied) if has_git and not commit else False
        if commit and history is not None:
            pin_history(git, history, commit)
            dirty = working_tree_dirty(
                git, source, tree_entries(git, history, commit), copied
            )
        date = git.date(history, commit) if commit and history is not None else ""
        yield Snapshot(
            workspace / "source",
            _identity(str(source), commit, date, "working-tree", dirty),
            history,
        )


def _review_side(
    git: Git, review: ReviewTarget, side: str, workspace: Path
) -> Snapshot:
    expected = review.base_sha if side == "base" else review.head_sha
    url = review.base_repo_url if side == "base" else review.head_repo_url
    verify_sha(expected)
    if not remote_url(url):
        source = _local_path(url)
        history = local_history(git, source, workspace / f"{side}.git")
        commit = git.resolve(history, expected)
        if commit != expected:
            raise RuntimeError("Local review object differs from its captured SHA")
    else:
        fallback_ref = review.head_fetch_ref if side == "head" else ""
        history, commit = remote_history(
            git,
            url,
            expected,
            workspace / f"{side}.git",
            expected,
            fallback_ref,
            review.base_repo_url,
        )
    return _ref_snapshot(git, history, commit, url, workspace / side)


@contextmanager
def acquire_comparison(
    target: str,
    base: str,
    head: str,
    *,
    review: ReviewTarget | None = None,
    timeout: float = 120.0,
):
    """Compare exact provider base/head objects or explicitly named local/remote refs."""
    git = Git(timeout)
    with tempfile.TemporaryDirectory(prefix="diff-gremlin-comparison-") as directory:
        workspace = Path(directory)
        if review:
            before = _review_side(git, review, "base", workspace)
            after = _review_side(git, review, "head", workspace)
        elif remote_url(target):
            before_history, before_sha = remote_history(
                git, target, base, workspace / "base.git"
            )
            after_history, after_sha = remote_history(
                git, target, head, workspace / "head.git"
            )
            before = _ref_snapshot(
                git, before_history, before_sha, target, workspace / "base"
            )
            after = _ref_snapshot(
                git, after_history, after_sha, target, workspace / "head"
            )
        else:
            source = _local_path(target)
            before_sha, after_sha = git.resolve(source, base), git.resolve(source, head)
            history = local_history(git, source, workspace / "history.git")
            before_history = history_view(
                git, history, workspace / "base.git", before_sha
            )
            after_history = history_view(
                git, history, workspace / "head.git", after_sha
            )
            before = _ref_snapshot(
                git, before_history, before_sha, str(source), workspace / "base"
            )
            after = _ref_snapshot(
                git, after_history, after_sha, str(source), workspace / "head"
            )
        yield SnapshotPair(before, after, review, before.identity.commit_sha)
