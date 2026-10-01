"""Collect bounded TypeScript diagnostics with fixed compiler options."""

from pathlib import Path

from diff_gremlin.analyzers.status import unavailable

from diff_gremlin.analyzers.javascript.installed import (
    installed_package,
    package_version,
    trusted_executable,
)
from diff_gremlin.analyzers.javascript.output import (
    evidence,
    failure_status,
    located_findings,
    natural,
    valid_run,
)
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult

_ID, _LABEL = "typescript.types.tsc", "TypeScript static types"


def _diagnostics(stdout, files):
    data = evidence(stdout, files)
    if not all(
        natural(data.get(k))
        for k in (
            "error_count",
            "warning_count",
            "dependency_count",
            "global_count",
        )
    ):
        raise ValueError("invalid diagnostic counts")
    findings = located_findings(data["findings"], files)
    if (
        len(findings) + data["global_count"]
        != data["error_count"] + data["warning_count"]
    ):
        raise ValueError("incomplete diagnostic counts")
    return data, findings


def _type_environment(ctx):
    package = installed_package(ctx, "tsc", "typescript")
    node = trusted_executable(ctx, "node")
    return (node, package) if node and package else None


def _type_metrics(data):
    return {
        key: data[key]
        for key in ("error_count", "warning_count", "dependency_count", "global_count")
    }


def _type_limit(data):
    return data["dependency_count"] > 0 or data["global_count"] > 0


def analyze_ts_types(ctx: ScanContext) -> StageResult:
    files = tuple(
        file for file in ctx.production_files if file.language == "typescript"
    )

    def absent(reason, status="missing"):
        return unavailable(
            _ID,
            _LABEL,
            "types",
            "typescript",
            reason,
            status=status,
            eligible_files=len(files),
        )

    if not files:
        return absent("No TypeScript production files", "skipped")
    environment = _type_environment(ctx)
    if environment is None:
        return absent("Installed trusted Node/TypeScript package unavailable")
    node, package = environment
    result = ctx.run(
        [
            node,
            str(Path(__file__).parent / "assets" / "types.cjs"),
            str(package),
            *(str(f.path.resolve()) for f in files),
        ],
        cwd=ctx.scratch,
    )
    if not valid_run(result):
        return absent(
            f"Controlled TypeScript invocation {result.status}; exit {result.returncode}",
            failure_status(result),
        )
    try:
        data, findings = _diagnostics(result.stdout, files)
    except (ValueError, TypeError):
        return absent(
            "Controlled TypeScript returned malformed or incomplete evidence", "failed"
        )
    limited = _type_limit(data)
    return StageResult(
        _ID,
        _LABEL,
        "types",
        "limited" if limited else "ok",
        "typescript",
        package_version(package),
        metrics=_type_metrics(data),
        findings=findings,
        reason="Fixed static options; unresolved dependencies/global diagnostics limit semantics"
        if limited
        else "Fixed static options; project configuration and implicit imports excluded",
        scope="standalone-static",
        eligible_files=len(files),
        analyzed_files=len(files),
        duration_seconds=result.duration_seconds,
    )
