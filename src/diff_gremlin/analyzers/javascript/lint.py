"""Run installed ESLint against an owned flat configuration."""

from pathlib import Path

from diff_gremlin.analyzers.status import unavailable

from diff_gremlin.analyzers.javascript.installed import (
    installed_package,
    package_version,
    sibling_package,
    trusted_executable,
)
from diff_gremlin.analyzers.javascript.output import evidence, located_findings, natural
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult

_ID, _LABEL = "javascript.lint.eslint", "JavaScript/TypeScript lint"


def analyze_js_lint(ctx: ScanContext) -> StageResult:
    files = tuple(
        file
        for file in ctx.production_files
        if file.language in {"javascript", "typescript"}
    )

    def absent(reason, status="missing"):
        return unavailable(
            _ID,
            _LABEL,
            "lint",
            "eslint",
            reason,
            status=status,
            eligible_files=len(files),
        )

    if not files:
        return absent("No JavaScript or TypeScript production files", "skipped")
    package = installed_package(ctx, "eslint", "eslint")
    node = trusted_executable(ctx, "node")
    if not package or not node:
        return absent("Installed trusted Node/ESLint package unavailable")
    dependencies = [
        sibling_package(package, name)
        for name in (
            "@typescript-eslint/parser",
            "@typescript-eslint/eslint-plugin",
            "globals",
        )
    ]
    if not all(dependencies):
        return absent(
            "Controlled ESLint parser/plugin/globals dependencies unavailable"
        )
    asset = Path(__file__).parent / "assets" / "lint.cjs"
    result = ctx.run(
        [
            node,
            str(asset),
            str(package),
            *(str(p) for p in dependencies),
            *(str(f.path.resolve()) for f in files),
        ],
        cwd=ctx.scratch,
    )
    if result.status != "ok" or result.returncode != 0:
        return absent(
            f"Controlled ESLint invocation {result.status}; exit {result.returncode}",
            result.status if result.status in {"missing", "timeout"} else "failed",
        )
    try:
        data = evidence(result.stdout, files)
        if not all(
            natural(data.get(k))
            for k in ("error_count", "warning_count", "fatal_count")
        ):
            raise ValueError("invalid diagnostic counts")
        findings = located_findings(data["findings"], files)
        if len(findings) != data["error_count"] + data["warning_count"]:
            raise ValueError("diagnostic counts differ from findings")
    except (ValueError, TypeError):
        return absent(
            "Controlled ESLint returned malformed or incomplete evidence", "failed"
        )
    return StageResult(
        _ID,
        _LABEL,
        "lint",
        "ok",
        "eslint",
        package_version(package),
        metrics={
            "issue_count": len(findings),
            "error_count": data["error_count"],
            "warning_count": data["warning_count"],
            "fatal_count": data["fatal_count"],
        },
        findings=findings,
        eligible_files=len(files),
        analyzed_files=len(files),
        duration_seconds=result.duration_seconds,
    )
