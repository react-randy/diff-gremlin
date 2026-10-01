"""Adapt installed TypeScript syntax evidence into JS/TS call observations."""

from pathlib import Path

from diff_gremlin.analyzers.javascript.installed import installed_package, trusted_executable
from diff_gremlin.analyzers.javascript.output import evidence, located_findings, natural, valid_run
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding


def observe_javascript_calls(
    ctx: ScanContext, files: tuple[SourceFile, ...]
) -> tuple[list[Finding], int, str]:
    """Return parser observations while retaining missing or invalid evidence as limited."""
    if not files:
        return [], 0, ""
    package, node = (
        installed_package(ctx, "tsc", "typescript"),
        trusted_executable(ctx, "node"),
    )
    if not package or not node:
        return [], 0, "Trusted TypeScript syntax parser unavailable for JS/TS calls"
    asset = Path(__file__).parent / "assets" / "execution.cjs"
    result = ctx.run(
        [node, str(asset), str(package), *(str(file.path.resolve()) for file in files)],
        cwd=ctx.scratch,
    )
    if not valid_run(result):
        return [], 0, f"JS/TS syntax parser {result.status}; exit {result.returncode}"
    try:
        data = evidence(result.stdout, files)
        if not natural(data.get("parse_errors")):
            raise ValueError("invalid parse error count")
        return (
            located_findings(data["findings"], files),
            len(files),
            "JS/TS syntax errors limit calls" if data["parse_errors"] else "",
        )
    except (ValueError, TypeError):
        return [], 0, "JS/TS parser output malformed or incomplete"
