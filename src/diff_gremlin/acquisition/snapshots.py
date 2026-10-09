"""Own disposable snapshot lifetimes for repository and review analysis."""

import tempfile
from contextlib import contextmanager
from pathlib import Path

from diff_gremlin.acquisition.changes import (
    changed_lines,
    comparison_history,
)
from diff_gremlin.acquisition.changes import (
    changed_paths as comparison_changed_paths,
)
from diff_gremlin.acquisition.git import Git, remote_url
from diff_gremlin.acquisition.objects import extract_tree, tree_entries
from diff_gremlin.acquisition.repositories import (
    history_view,
    local_history,
    pin_history,
    remote_history,
    verify_sha,
)
from diff_gremlin.acquisition.selection import PathSelection, normalize_paths
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
    git: Git,
    history: Path,
    commit: str,
    target: str,
    destination: Path,
    selection: PathSelection | None = None,
) -> Snapshot:
    pin_history(git, history, commit)
    scope_manifest = []
    counts = {}
    extract_tree(
        git,
        history,
        commit,
        destination,
        scope_manifest=scope_manifest,
        selection=selection,
        selection_counts=counts,
    )
    return Snapshot(
        destination,
        _identity(target, commit, git.date(history, commit), "commit"),
        history,
        tuple(sorted(scope_manifest, key=lambda row: row.relative_path)),
        selection.receipt(counts["total"], counts["selected"]) if selection else None,
    )


def _working_snapshot(
    git: Git,
    source: Path,
    destination: Path,
    history: Path | None,
    commit: str,
    has_git: bool,
) -> Snapshot:
    scope_manifest = []
    copied = copy_working_tree(
        source,
        destination,
        deadline=git.deadline,
        scope_manifest=scope_manifest,
        oid_length=len(commit) if commit else 40,
    )
    dirty = bool(copied) if has_git and not commit else False
    if commit and history is not None:
        pin_history(git, history, commit)
        dirty = working_tree_dirty(
            git, source, tree_entries(git, history, commit), copied
        )
    date = git.date(history, commit) if commit and history is not None else ""
    return Snapshot(
        destination,
        _identity(str(source), commit, date, "working-tree", dirty),
        history,
        tuple(sorted(scope_manifest, key=lambda row: row.relative_path)),
    )


def _local_commit(git: Git, source: Path, ref: str | None, bare: bool) -> str:
    commits = git.run(["rev-list", "--all", "--max-count=1"], cwd=source).strip()
    return git.resolve(source, ref or "HEAD") if commits or ref or bare else ""


def _local_source(git: Git, target: str, ref: str | None, workspace: Path) -> Snapshot:
    source = _local_path(target)
    bare = (source / "HEAD").is_file() and (source / "objects").is_dir()
    has_git = (source / ".git").exists() or bare
    if ref and not has_git:
        raise ValueError("An explicit ref requires a local Git repository")
    history, commit = None, ""
    if has_git:
        history = local_history(git, source, workspace / "history.git")
        commit = _local_commit(git, source, ref, bare)
        if ref or bare:
            return _ref_snapshot(
                git, history, commit, str(source), workspace / "source"
            )
    return _working_snapshot(
        git, source, workspace / "source", history, commit, has_git
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
        else:
            yield _local_source(git, target, ref, workspace)


def _review_history(
    git: Git, review: ReviewTarget, side: str, workspace: Path
) -> tuple[Path, str, str]:
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
    return history, commit, url


@contextmanager
def acquire_comparison(
    target: str,
    base: str,
    head: str,
    *,
    review: ReviewTarget | None = None,
    timeout: float = 120.0,
    paths: tuple[str, ...] = (),
    changed_paths: bool = False,
):
    """Compare exact provider base/head objects or explicitly named local/remote refs."""
    git = Git(timeout)
    prefixes = normalize_paths(paths)
    with tempfile.TemporaryDirectory(prefix="diff-gremlin-comparison-") as directory:
        workspace = Path(directory)
        if review:
            before_history, before_sha, before_target = _review_history(
                git, review, "base", workspace
            )
            after_history, after_sha, after_target = _review_history(
                git, review, "head", workspace
            )
        elif remote_url(target):
            before_history, before_sha = remote_history(
                git, target, base, workspace / "base.git"
            )
            after_history, after_sha = remote_history(
                git, target, head, workspace / "head.git"
            )
            before_target = after_target = target
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
            before_target = after_target = str(source)
        metadata_history = comparison_history(
            git, before_history, after_history, workspace / "comparison.git"
        )
        changed = (
            frozenset(
                comparison_changed_paths(git, metadata_history, before_sha, after_sha)
            )
            if changed_paths
            else None
        )
        selection = (
            PathSelection(prefixes, changed) if prefixes or changed_paths else None
        )
        before = _ref_snapshot(
            git,
            before_history,
            before_sha,
            before_target,
            workspace / "base",
            selection,
        )
        after = _ref_snapshot(
            git, after_history, after_sha, after_target, workspace / "head", selection
        )
        base_lines, head_lines = changed_lines(
            git, metadata_history, before_sha, after_sha, selection
        )
        yield SnapshotPair(before, after, review, before_sha, base_lines, head_lines)
