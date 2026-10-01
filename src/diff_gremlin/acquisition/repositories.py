"""Populate owned bare repositories with inert local or remote objects."""

import re
from pathlib import Path

from diff_gremlin.acquisition.auth import git_auth
from diff_gremlin.acquisition.git import Git
from diff_gremlin.acquisition.objects import copy_object_store


def local_history(git: Git, source: Path, destination: Path) -> Path:
    common = Path(git.run(["rev-parse", "--git-common-dir"], cwd=source).strip())
    common = common if common.is_absolute() else source / common
    object_format = git.run(["rev-parse", "--show-object-format"], cwd=source).strip()
    if object_format not in {"sha1", "sha256"}:
        raise RuntimeError("Local Git object format is unsupported")
    git.run(["init", "--bare", f"--object-format={object_format}", str(destination)])
    try:
        copy_object_store(
            common.resolve() / "objects", destination / "objects", deadline=git.deadline
        )
    except OSError as exc:
        raise RuntimeError(
            "Local Git object storage could not be copied safely"
        ) from exc
    return destination


def remote_history(
    git: Git,
    url: str,
    ref: str,
    destination: Path,
    expected: str = "",
    fallback_ref: str = "",
    fallback_url: str = "",
) -> tuple[Path, str]:
    fmt = "sha256" if len(expected) == 64 else "sha1"
    git.run(["init", "--bare", f"--object-format={fmt}", str(destination)])
    try:
        _fetch(git, destination, url, ref)
    except RuntimeError:
        if not fallback_ref:
            raise
        _fetch(git, destination, fallback_url or url, fallback_ref)
    commit = git.resolve(destination, "FETCH_HEAD")
    if expected and commit != expected:
        raise RuntimeError(
            "Fetched review object does not match the captured provider SHA; resolve the review again"
        )
    pin_history(git, destination, commit)
    return destination, commit


def _fetch(git: Git, repo: Path, url: str, ref: str) -> None:
    if not ref or ref.startswith("-") or "\0" in ref:
        raise ValueError("Remote ref must be a nonempty commit or ref name")
    with git_auth(url, timeout=min(10.0, git.remaining())) as env:
        git.run(["fetch", "--no-tags", "--depth=50", "--", url, ref], cwd=repo, env=env)


def verify_sha(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9a-f]{40}|[0-9a-f]{64}", value
    ):
        raise ValueError("Review acquisition requires a full lowercase commit SHA")


def pin_history(git: Git, repo: Path, commit: str) -> None:
    """Make the owned history HEAD identify the snapshot examined by its consumer."""
    git.run(["update-ref", "refs/heads/snapshot", commit], cwd=repo)
    git.run(["symbolic-ref", "HEAD", "refs/heads/snapshot"], cwd=repo)


def history_view(git: Git, source: Path, destination: Path, commit: str) -> Path:
    """Give comparison sides independent HEADs over one owned object store."""
    fmt = git.run(["rev-parse", "--show-object-format"], cwd=source).strip()
    git.run(["init", "--bare", f"--object-format={fmt}", str(destination)])
    (destination / "objects" / "info" / "alternates").write_text(
        str(source / "objects") + "\n"
    )
    pin_history(git, destination, commit)
    return destination
