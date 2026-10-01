"""Extract independently validated located unreachable-code observations."""

from diff_gremlin.analyzers.locations import relative_location
from diff_gremlin.analyzers.python.pyscn_coverage import component_valid
from diff_gremlin.analyzers.python.schema import count, list_value, object_value
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding


def _diagnostic(
    ctx: ScanContext,
    files: tuple[SourceFile, ...],
    file_path: str,
    name: str,
    finding_value: object,
) -> Finding:
    item = object_value(finding_value)
    location = object_value(item.get("location"))
    path = relative_location(ctx.root, location.get("file_path"), files)
    start, end = (
        count(location.get("start_line")),
        count(location.get("end_line")),
    )
    reason, severity = item.get("reason"), item.get("severity")
    if (
        path != file_path
        or start < 1
        or end < start
        or not isinstance(reason, str)
        or not reason
    ):
        raise ValueError("invalid dead code diagnostic location")
    if severity not in ("critical", "warning", "info"):
        raise ValueError("invalid dead code diagnostic severity")
    return Finding(
        rule=f"pyscn.deadcode.{reason}",
        message=f"Unreachable code: {reason.replace('_', ' ')}",
        severity="medium" if severity == "critical" else "low",
        path=path,
        line=start,
        symbol=name,
    )


def _located_findings(
    ctx: ScanContext, files: tuple[SourceFile, ...], dead: dict
) -> list[Finding]:
    findings = []
    for file_value in list_value(dead.get("files")):
        file = object_value(file_value)
        file_path = relative_location(ctx.root, file.get("file_path"), files)
        for function_value in list_value(file.get("functions")):
            function = object_value(function_value)
            name = function.get("name")
            if not isinstance(name, str):
                raise TypeError("missing dead code function name")
            for finding_value in list_value(function.get("findings")):
                findings.append(_diagnostic(ctx, files, file_path, name, finding_value))
    return findings


def deadcode_observations(
    ctx: ScanContext, files: tuple[SourceFile, ...], data: dict
) -> tuple[dict, list[Finding]]:
    summary = object_value(data.get("summary"))
    if summary.get("dead_code_enabled") is not True or not component_valid(
        data, "dead_code"
    ):
        raise ValueError("PyScn dead code analysis unavailable")
    expected = count(summary.get("dead_code_count"))
    dead = object_value(data.get("dead_code"))
    detail = object_value(dead.get("summary"))
    if count(detail.get("total_findings")) != expected:
        raise ValueError("dead code finding counts disagree")
    if count(detail.get("total_files")) != count(summary.get("analyzed_files")):
        raise ValueError("dead code coverage differs from snapshot coverage")
    findings = _located_findings(ctx, files, dead)
    if len(findings) != expected:
        raise ValueError("dead code summary differs from located findings")
    return {"issue_count": expected}, findings
