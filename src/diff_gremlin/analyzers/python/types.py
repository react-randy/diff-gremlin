"""Produce Python type diagnostics from a controlled Pyrefly invocation."""

import json
import sys
import sysconfig
from functools import partial
from pathlib import Path
from tempfile import TemporaryDirectory

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
from diff_gremlin.domain.process import RunResult
from diff_gremlin.domain.stages import StageResult

_ID = "python.types.pyrefly"


def _config(root: Path) -> str:
    paths = [str(root), str(root / "src")]
    return "project-includes = []\nsearch-path = " + json.dumps(paths) + "\n"


def _diagnostics(
    ctx: ScanContext, files: tuple[SourceFile, ...], text: str
) -> tuple[list[Finding], int, int]:
    values = list_value(object_value(json_value(text)).get("errors"))
    findings = []
    errors = warnings = 0
    for value in values:
        item = object_value(value)
        path = relative_location(ctx.root, item.get("path"), files)
        line, column = count(item.get("line")), count(item.get("column"))
        name, severity = item.get("name"), item.get("severity")
        if (
            line < 1
            or column < 1
            or not isinstance(name, str)
            or not name
            or severity not in ("error", "warn", "warning", "info")
        ):
            raise ValueError("invalid Pyrefly diagnostic")
        errors += severity == "error"
        warnings += severity in ("warn", "warning")
        findings.append(
            Finding(
                rule=f"pyrefly.{name}",
                message=f"Pyrefly {name} diagnostic",
                severity="medium" if severity == "error" else "low",
                path=path,
                line=line,
                column=column,
            )
        )
    return findings, errors, warnings


def _run_pyrefly(ctx: ScanContext, files: tuple[SourceFile, ...]) -> RunResult:
    with TemporaryDirectory(prefix="pyrefly-", dir=ctx.scratch) as directory:
        config = Path(directory) / "pyrefly.toml"
        config.write_text(_config(ctx.root), encoding="utf-8")
        return ctx.run(
            [
                "pyrefly",
                "check",
                "--config",
                str(config),
                "--output-format",
                "json",
                "--output",
                "-",
                "--relative-to",
                str(ctx.root),
                "--skip-interpreter-query",
                "--site-package-path",
                sysconfig.get_path("purelib"),
                "--use-ignore-files=false",
                "--ignore-errors-in-generated-code=false",
                "--disable-search-path-heuristics=true",
                "--python-version",
                f"{sys.version_info.major}.{sys.version_info.minor}",
                "--min-severity",
                "warn",
                "--summary",
                "none",
                "--color",
                "never",
                "--",
                *(str(file.path) for file in files),
            ],
            cwd=ctx.scratch,
        )


def _type_stage(
    ctx: ScanContext,
    files: tuple[SourceFile, ...],
    findings: list[Finding],
    errors: int,
    warnings: int,
    duration: float,
) -> StageResult:
    unresolved = any(
        finding.rule in ("pyrefly.import-error", "pyrefly.missing-import") for finding in findings
    )
    return StageResult(
        _ID,
        "Python types",
        "types",
        "limited" if unresolved else "ok",
        "pyrefly",
        version=tool_version(ctx, "pyrefly"),
        metrics={
            "error_count": errors,
            "warning_count": warnings,
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "dependency_resolution": "snapshot-bundled-typeshed-and-installed-tool-environment",
        },
        findings=findings,
        reason="Imports unavailable in the static tool environment" if unresolved else "",
        eligible_files=len(files),
        analyzed_files=len(files),
        duration_seconds=duration,
    )


def analyze_python_types(ctx: ScanContext) -> StageResult:
    files = tuple(file for file in ctx.production_files if file.language == "python")
    failure = partial(
        unavailable, _ID, "Python types", "types", "pyrefly", eligible_files=len(files)
    )
    if not files:
        return failure(reason="No production Python files", status="unsupported")
    try:
        result = _run_pyrefly(ctx, files)
    except OSError:
        return failure(reason="Could not create controlled Pyrefly configuration", status="failed")
    status = execution_status(result, (0, 1))
    if status is not None:
        return failure(reason="Pyrefly execution did not complete valid analysis", status=status)
    try:
        findings, errors, warnings = _diagnostics(ctx, files, result.stdout)
        if (result.returncode == 1) != bool(errors):
            raise ValueError("Pyrefly exit status disagrees with error count")
    except (ValueError, TypeError):
        return failure(reason="Pyrefly output failed diagnostic schema validation", status="failed")
    return _type_stage(ctx, files, findings, errors, warnings, result.duration_seconds)
