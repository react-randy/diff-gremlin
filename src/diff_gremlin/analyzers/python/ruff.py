"""Produce Python lint observations from isolated Ruff JSON output."""

import time
from dataclasses import replace
from functools import partial

from diff_gremlin.analyzers.batches import collect_batches
from diff_gremlin.analyzers.locations import SourceLocations
from diff_gremlin.analyzers.python.schema import (
    count,
    json_value,
    list_value,
    object_value,
)
from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.process import RunResult
from diff_gremlin.domain.stages import StageResult

_ID = "python.lint.ruff"


def _findings(
    ctx: ScanContext, files: tuple[SourceFile, ...], stdout: str
) -> list[Finding]:
    locations = SourceLocations(ctx.root, files)
    findings = []
    for value in list_value(json_value(stdout)):
        item = object_value(value)
        location = object_value(item.get("location"))
        path = locations.relative(item.get("filename"))
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


def _validated_batch(
    ctx: ScanContext, files: tuple[SourceFile, ...], result: RunResult
) -> list[Finding]:
    findings = _findings(ctx, files, result.stdout)
    if (result.returncode == 1) != bool(findings):
        raise ValueError("Ruff exit status disagrees with diagnostic count")
    return findings


def analyze_ruff(ctx: ScanContext) -> StageResult:
    files = tuple(file for file in ctx.production_files if file.language == "python")
    failure = partial(
        unavailable, _ID, "Python lint", "lint", "ruff", eligible_files=len(files)
    )
    if not files:
        return failure(reason="No production Python files", status="unsupported")
    started = time.monotonic()
    evidence = collect_batches(
        ctx,
        files,
        ["ruff", "check", "--isolated", "--no-cache", "--output-format", "json"],
        (0, 1),
        partial(_validated_batch, ctx),
    )
    version = (
        tool_version(replace(ctx, timeout=evidence.remaining_time()), "ruff")
        if evidence.remaining_time() > 0
        else ""
    )
    return StageResult(
        _ID,
        "Python lint",
        "lint",
        evidence.status,
        "ruff",
        version=version,
        metrics={"issue_count": len(evidence.values)} if evidence.analyzed else {},
        findings=evidence.values,
        reason=f"Ruff {evidence.reason}" if evidence.reason else "",
        eligible_files=len(files),
        analyzed_files=evidence.analyzed,
        duration_seconds=time.monotonic() - started,
    )
