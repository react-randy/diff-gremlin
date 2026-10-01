"""Validate PyScn snapshot identity and analyzed Python file coverage."""

from diff_gremlin.analyzers.locations import SourceLocations
from diff_gremlin.analyzers.python.schema import count, list_value, object_value
from diff_gremlin.domain.context import ScanContext, SourceFile


def coverage(
    ctx: ScanContext, files: tuple[SourceFile, ...], data: dict
) -> tuple[int, bool]:
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        raise ValueError("unsupported PyScn schema version")
    summary = object_value(data.get("summary"))
    total = count(summary.get("total_files"))
    analyzed = count(summary.get("analyzed_files"))
    skipped = count(summary.get("skipped_files"))
    if total != len(files) or analyzed + skipped != total or analyzed == 0:
        raise ValueError("invalid PyScn file coverage counts")
    complexity = object_value(data.get("complexity"))
    locations = SourceLocations(ctx.root, files)
    paths = []
    for value in list_value(complexity.get("raw_metrics")):
        item = object_value(value)
        paths.append(locations.relative(item.get("file_path")))
    if len(paths) != analyzed or len(set(paths)) != analyzed:
        raise ValueError("PyScn analyzed file locations disagree with summary")
    return analyzed, analyzed < len(files)


def component_valid(data: dict, component: str) -> bool:
    """Reject component errors, even when the unified process exits zero."""
    value = object_value(data.get(component))
    errors = list_value(value.get("errors"))
    return not errors
