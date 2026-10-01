"""Name the scanned bytes separately from their Git anchor."""

from diff_gremlin.domain.sources import SourceIdentity


def revision_label(source: SourceIdentity) -> str:
    if source.mode != "working-tree":
        return "commit " + source.commit_sha
    if not source.commit_sha:
        return "working tree (no Git commit)"
    state = "dirty" if source.dirty else "clean"
    return f"working tree ({state}; HEAD anchor {source.commit_sha})"
