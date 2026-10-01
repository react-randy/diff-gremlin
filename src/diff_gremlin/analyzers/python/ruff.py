"""Produce Python lint observations from isolated Ruff JSON output."""

from functools import partial

from diff_gremlin.analyzers.locations import relative_location
from diff_gremlin.analyzers.python.schema import (
    count,
    json_value,
    list_value,
    object_value,
)
from diff_gremlin.analyzers.status import execution_status, unavailable
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_ID = "python.lint.ruff"


def _findings(
    ctx: ScanContext, files: tuple[SourceFile, ...], stdout: str
) -> list[Finding]:
    findings = []
    for value in list_value(json_value(stdout)):
        item = object_value(value)
        location = object_value(item.get("location"))
        path = relative_location(ctx.root, item.get("filename"), files)
        line, column = count(location.get("row")), count(location.get("column"))
        if line < 1 or column < 1 or not isinstance(item.get("message"), str):
            raise ValueError("invalid Ruff diagnostic")
        rule = item.get("code")
        if not isinstance(rule, str) or not rule:
            raise ValueError("missing Ruff diagnostic rule")
        # Tool messages can quote source literals; publish the rule's explanation only.
        findings.append(
            Finding(
                rule=f"ruff.{rule}",
                message=f"Ruff {rule} diagnostic",
                path=path,
                line=line,
                column=column,
            )
        )
    return findings


def analyze_ruff(ctx: ScanContext) -> StageResult:
    files = tuple(file for file in ctx.production_files if file.language == "python")
    failure = partial(
        unavailable, _ID, "Python lint", "lint", "ruff", eligible_files=len(files)
    )
    if not files:
        return failure(reason="No production Python files", status="unsupported")
    result = ctx.run(
        [
            "ruff",
            "check",
            "--isolated",
            "--no-cache",
            "--output-format",
            "json",
            "--",
            *(str(file.path) for file in files),
        ],
        cwd=ctx.scratch,
    )
    status = execution_status(result, (0, 1))
    if status is not None:
        return failure(
            reason="Ruff execution did not complete valid analysis", status=status
        )
    try:
        findings = _findings(ctx, files, result.stdout)
        if (result.returncode == 1) != bool(findings):
            raise ValueError("Ruff exit status disagrees with diagnostic count")
    except (ValueError, TypeError):
        return failure(
            reason="Ruff output failed diagnostic schema validation", status="failed"
        )
    return StageResult(
        _ID,
        "Python lint",
        "lint",
        "ok",
        "ruff",
        version=tool_version(ctx, "ruff"),
        metrics={"issue_count": len(findings)},
        findings=findings,
        eligible_files=len(files),
        analyzed_files=len(files),
        duration_seconds=result.duration_seconds,
    )
