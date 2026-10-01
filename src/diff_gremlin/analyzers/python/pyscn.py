"""Expose independent facts from one fresh controlled PyScn JSON run."""

from pathlib import Path
from tempfile import TemporaryDirectory

from diff_gremlin.analyzers.python.pyscn_clones import clone_observations
from diff_gremlin.analyzers.python.pyscn_coverage import component_valid, coverage
from diff_gremlin.analyzers.python.pyscn_deadcode import deadcode_observations
from diff_gremlin.analyzers.python.schema import json_value, number, object_value
from diff_gremlin.analyzers.status import execution_status, unavailable
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import Category, StageResult, StageStatus

_CAPABILITIES: tuple[tuple[str, str, Category, bool], ...] = (
    ("python.health.pyscn", "Python health", "health", False),
    ("python.duplication.pyscn", "Python duplication", "duplication", True),
    ("python.deadcode.pyscn", "Python dead code", "structure", True),
)


def _unobserved(reason: str, status: StageStatus, eligible: int) -> list[StageResult]:
    return [
        unavailable(
            stage_id,
            label,
            category,
            "pyscn",
            reason,
            status=status,
            eligible_files=eligible,
            required=required,
        )
        for stage_id, label, category, required in _CAPABILITIES
    ]


def _health(data: dict) -> tuple[dict, list]:
    if not component_valid(data, "complexity") or not component_valid(
        data, "dead_code"
    ):
        raise ValueError("PyScn health includes failed components")
    clone = object_value(data.get("clone"))
    if clone.get("success") is not True:
        raise ValueError("PyScn health includes failed clone analysis")
    return {
        "health_score": number(object_value(data.get("summary")).get("health_score"))
    }, []


def analyze_pyscn(ctx: ScanContext) -> list[StageResult]:
    files = tuple(file for file in ctx.production_files if file.language == "python")
    if not files:
        return _unobserved("No production Python files", "unsupported", 0)
    try:
        with TemporaryDirectory(prefix="pyscn-", dir=ctx.scratch) as directory:
            config = Path(directory) / "pyscn.toml"
            config.write_text("", encoding="utf-8")
            result = ctx.run(
                [
                    "pyscn",
                    "analyze",
                    "--config",
                    str(config),
                    "--json",
                    "--output",
                    "-",
                    "--no-open",
                    "--",
                    *(str(file.path) for file in files),
                ],
                cwd=ctx.scratch,
            )
    except OSError:
        return _unobserved(
            "Could not create controlled PyScn configuration", "failed", len(files)
        )
    status = execution_status(result, (0,))
    if status is not None:
        return _unobserved(
            "PyScn execution did not complete valid analysis", status, len(files)
        )
    try:
        data = object_value(json_value(result.stdout))
        analyzed, partial = coverage(ctx, files, data)
    except (ValueError, TypeError):
        return _unobserved(
            "PyScn output failed snapshot schema or coverage validation",
            "failed",
            len(files),
        )
    version = tool_version(ctx, "pyscn")
    parsers = (
        lambda: _health(data),
        lambda: clone_observations(ctx, files, data),
        lambda: deadcode_observations(ctx, files, data),
    )
    stages = []
    for (stage_id, label, category, required), parser in zip(
        _CAPABILITIES, parsers, strict=True
    ):
        try:
            metrics, findings = parser()
        except (ValueError, TypeError):
            stages.append(
                unavailable(
                    stage_id,
                    label,
                    category,
                    "pyscn",
                    "PyScn component failed schema or result validation",
                    status="failed",
                    eligible_files=len(files),
                    required=required,
                )
            )
            continue
        stages.append(
            StageResult(
                stage_id,
                label,
                category,
                "limited" if partial else "ok",
                "pyscn",
                version=version,
                metrics=metrics,
                findings=findings,
                required=required,
                analyzed_files=analyzed,
                eligible_files=len(files),
                reason="PyScn skipped eligible Python files" if partial else "",
                duration_seconds=result.duration_seconds,
            )
        )
    return stages
