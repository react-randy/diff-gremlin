"""Collect bounded TypeScript diagnostics with fixed compiler options."""

from pathlib import Path

from diff_gremlin.analyzers.status import unavailable

from diff_gremlin.analyzers.javascript.installed import (
    installed_package,
    package_version,
    trusted_executable,
)
from diff_gremlin.analyzers.javascript.output import evidence, located_findings, natural
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult

_ID, _LABEL = "typescript.types.tsc", "TypeScript static types"


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
    package = installed_package(ctx, "tsc", "typescript")
    node = trusted_executable(ctx, "node")
    if not node or not package:
        return absent("Installed trusted Node/TypeScript package unavailable")
    result = ctx.run(
        [
            node,
            str(Path(__file__).parent / "assets" / "types.cjs"),
            str(package),
            *(str(f.path.resolve()) for f in files),
        ],
        cwd=ctx.scratch,
    )
    if result.status != "ok" or result.returncode != 0:
        return absent(
            f"Controlled TypeScript invocation {result.status}; exit {result.returncode}",
            result.status if result.status in {"missing", "timeout"} else "failed",
        )
    try:
        data = evidence(result.stdout, files)
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
    except (ValueError, TypeError):
        return absent(
            "Controlled TypeScript returned malformed or incomplete evidence", "failed"
        )
    limited = data["dependency_count"] > 0 or data["global_count"] > 0
    return StageResult(
        _ID,
        _LABEL,
        "types",
        "limited" if limited else "ok",
        "typescript",
        package_version(package),
        metrics={
            k: data[k]
            for k in (
                "error_count",
                "warning_count",
                "dependency_count",
                "global_count",
            )
        },
        findings=findings,
        reason="Fixed static options; unresolved dependencies/global diagnostics limit semantics"
        if limited
        else "Fixed static options; project configuration and implicit imports excluded",
        scope="standalone-static",
        eligible_files=len(files),
        analyzed_files=len(files),
        duration_seconds=result.duration_seconds,
    )
