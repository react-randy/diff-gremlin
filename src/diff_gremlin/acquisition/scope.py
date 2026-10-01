"""Select captured content and declare every nonmaterialized regular path."""

from diff_gremlin.domain.sources import SourceScopeEntry
from diff_gremlin.source_scope import classify_content


def content_scope(path: str, content: bytes, size: int, limit: int):
    classification, reason = classify_content(path, content)
    if classification == "binary-asset":
        return SourceScopeEntry(path, size, classification, reason)
    if size > limit:
        return SourceScopeEntry(
            path,
            size,
            "possible-source",
            "Content exceeds per-file text acquisition budget",
        )
    return None


def working_scope(path, mode, content, size, oid, *, limit, exhausted):
    """Declare capture/selection gaps while preserving binary and link scope."""
    if mode != "120000" and not oid:
        return SourceScopeEntry(
            path,
            size,
            "possible-source",
            "Content identity unavailable: read budget exhausted or file changed",
        )
    omission = (
        content_scope(path, content, max(size, len(content)), limit)
        if mode != "120000"
        else None
    )
    if omission is None and exhausted:
        return SourceScopeEntry(
            path,
            size,
            "possible-source",
            "Content exceeds aggregate text acquisition budget",
        )
    return omission
