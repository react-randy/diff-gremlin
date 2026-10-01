"""Report informational Python maintainability index without duplicate CC."""

import re
import sys
from functools import partial
from pathlib import Path

from diff_gremlin.analyzers.locations import relative_location
from diff_gremlin.analyzers.python.schema import json_value, number, object_value
from diff_gremlin.analyzers.status import execution_status, unavailable
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_ID = "python.maintainability.radon"


def _indices(
    ctx: ScanContext, files: tuple[SourceFile, ...], text: str
) -> tuple[str, dict[str, float]]:
    report = object_value(json_value(text))
    version = report.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("invalid Radon version identity")
    rows = {}
    for location, value in object_value(report.get("files")).items():
        path = relative_location(ctx.root, location, files)
        item = object_value(value)
        rows[path] = number(item.get("mi"))
    if set(rows) != {file.relative_path for file in files}:
        raise ValueError("Radon did not cover the eligible inventory")
    return version, rows


def analyze_maintainability(ctx: ScanContext) -> StageResult:
    files = tuple(file for file in ctx.production_files if file.language == "python")
    failure = partial(
        unavailable,
        _ID,
        "Python maintainability",
        "maintainability",
        "radon",
        eligible_files=len(files),
        required=False,
    )
    if not files:
        return failure(reason="No production Python files", status="unsupported")
    result = ctx.run(
        [
            sys.executable,
            "-I",
            str(Path(__file__).with_name("radon_driver.py")),
            *(str(file.path) for file in files),
        ],
        cwd=ctx.scratch,
    )
    if result.status == "ok" and result.returncode == 3:
        return failure(reason="Radon package is not installed", status="missing")
    status = execution_status(result, (0,))
    if status is not None:
        return failure(
            reason="Radon MI execution did not complete valid analysis", status=status
        )
    try:
        version, indices = _indices(ctx, files, result.stdout)
    except (ValueError, TypeError):
        return failure(
            reason="Radon MI output failed schema or coverage validation",
            status="failed",
        )
    findings = [
        Finding(
            rule="radon.low-mi",
            message=f"Maintainability index is {value:.1f}",
            severity="info",
            path=path,
        )
        for path, value in sorted(indices.items())
        if value < 20
    ]
    return StageResult(
        _ID,
        "Python maintainability",
        "maintainability",
        "ok",
        "radon",
        version=version,
        metrics={"average_mi": sum(indices.values()) / len(indices)},
        findings=findings,
        required=False,
        analyzed_files=len(files),
        eligible_files=len(files),
        duration_seconds=result.duration_seconds,
    )
