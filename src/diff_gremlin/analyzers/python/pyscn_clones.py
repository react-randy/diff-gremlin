"""Extract validated duplication percentage and located PyScn clone groups."""

from diff_gremlin.analyzers.locations import SourceLocations
from diff_gremlin.analyzers.python.schema import count, list_value, number, object_value
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding


def _clone_fragment(
    locations: SourceLocations, identity: int, fragment: object
) -> Finding:
    location = object_value(object_value(fragment).get("location"))
    path = locations.relative(location.get("file_path"))
    start, end = (
        count(location.get("start_line")),
        count(location.get("end_line")),
    )
    if start < 1 or end < start:
        raise ValueError("invalid clone fragment location")
    return Finding(
        rule="pyscn.clone",
        message=f"Code participates in clone group {identity}",
        severity="low",
        path=path,
        line=start,
    )


def _group_findings(
    ctx: ScanContext, files: tuple[SourceFile, ...], groups: list
) -> list[Finding]:
    locations = SourceLocations(ctx.root, files)
    findings = []
    seen_ids = set()
    for value in groups:
        group = object_value(value)
        identity = count(group.get("id"))
        if identity in seen_ids:
            raise ValueError("duplicate PyScn clone group identity")
        seen_ids.add(identity)
        fragments = list_value(group.get("clones"))
        if len(fragments) < 2:
            raise ValueError("clone group has fewer than two fragments")
        for fragment in fragments:
            findings.append(_clone_fragment(locations, identity, fragment))
    return findings


def clone_observations(
    ctx: ScanContext, files: tuple[SourceFile, ...], data: dict
) -> tuple[dict, list[Finding]]:
    summary = object_value(data.get("summary"))
    if summary.get("clone_enabled") is not True:
        raise ValueError("PyScn clone analysis disabled")
    number(summary.get("duplication_score"))
    percent = number(summary.get("code_duplication_percentage"))
    expected = count(summary.get("clone_groups"))
    clone = object_value(data.get("clone"))
    if clone.get("success") is not True:
        raise ValueError("PyScn clone analysis did not succeed")
    stats = object_value(clone.get("statistics"))
    analyzed = count(stats.get("files_analyzed"))
    if analyzed != count(summary.get("analyzed_files")):
        raise ValueError("PyScn clone coverage differs from snapshot coverage")
    groups = list_value(clone.get("clone_groups"))
    if len(groups) != expected or count(stats.get("total_clone_groups")) != expected:
        raise ValueError("PyScn clone group count differs from report rows")
    return {"duplication_percent": percent, "clone_groups": expected}, _group_findings(
        ctx, files, groups
    )
