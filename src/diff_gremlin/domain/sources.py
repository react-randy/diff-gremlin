"""Immutable source identities for snapshots and comparisons."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    target: str
    name: str
    commit_sha: str = ""
    commit_date: str = ""
    mode: str = "working-tree"
    dirty: bool = False


@dataclass(frozen=True, slots=True)
class SourceScopeEntry:
    """A declared exclusion or omission from current text analysis."""

    relative_path: str
    size_bytes: int
    classification: str
    reason: str


@dataclass(frozen=True, slots=True)
class Snapshot:
    root: Path
    identity: SourceIdentity
    history_repo: Path | None = None
    scope_manifest: tuple[SourceScopeEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class ReviewTarget:
    provider: str
    url: str
    repo_slug: str
    request_id: int
    base_repo_url: str
    head_repo_url: str
    base_sha: str
    head_sha: str
    base_ref: str = ""
    head_ref: str = ""
    head_fetch_ref: str = ""


@dataclass(frozen=True, slots=True)
class SnapshotPair:
    base: Snapshot
    head: Snapshot
    review: ReviewTarget | None = None
    comparison_base_sha: str = ""
