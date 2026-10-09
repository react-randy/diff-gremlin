"""Extract validated duplication percentage and located PyScn clone groups."""

from diff_gremlin.analyzers.locations import SourceLocations
from diff_gremlin.analyzers.python.schema import count, list_value, number, object_value
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.inventory import MAX_FILE_BYTES, MAX_TREE_BYTES


class _CloneRanges:
    """Check physical Python line ranges with bounded reads of captured bytes."""

    def __init__(self, files: tuple[SourceFile, ...]) -> None:
        self.files = {file.relative_path: file for file in files}
        self.lines: dict[str, int] = {}
        self.remaining = MAX_TREE_BYTES

    def validate(self, path: str, end: int) -> None:
        if path not in self.lines:
            file = self.files[path]
            if not 0 <= file.size_bytes <= min(self.remaining, MAX_FILE_BYTES):
                raise ValueError("PyScn clone source exceeds captured read budget")
            try:
                with file.path.open("rb") as stream:
                    source = stream.read(file.size_bytes + 1)
            except OSError as error:
                raise ValueError("PyScn clone source cannot be read") from error
            if len(source) != file.size_bytes:
                raise ValueError("PyScn clone source differs from captured size")
            self.remaining -= len(source)
            self.lines[path] = (
                source.replace(b"\r\n", b"\n").replace(b"\r", b"\n").count(b"\n") + 1
            )
        if end > self.lines[path]:
            raise ValueError("PyScn clone fragment line outside captured source")


def _clone_fragment(
    locations: SourceLocations,
    ranges: _CloneRanges,
    identity: int,
    fragment: object,
) -> Finding:
    location = object_value(object_value(fragment).get("location"))
    path = locations.relative(location.get("file_path"))
    start, end = (
        count(location.get("start_line")),
        count(location.get("end_line")),
    )
    if start < 1 or end < start:
        raise ValueError("invalid clone fragment location")
    ranges.validate(path, end)
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
    ranges = _CloneRanges(files)
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
            findings.append(_clone_fragment(locations, ranges, identity, fragment))
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
