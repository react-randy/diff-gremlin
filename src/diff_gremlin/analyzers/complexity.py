"""Measure production function cyclomatic complexity once with Lizard."""

import xml.etree.ElementTree as ET
from functools import partial

from diff_gremlin.analyzers.complexity_output import observations
from diff_gremlin.analyzers.status import execution_status, unavailable
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_ID = "complexity.lizard"
SUPPORTED_SUFFIXES = frozenset(
    {
        ".py",
        ".java",
        ".js",
        ".cjs",
        ".mjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".c",
        ".h",
        ".cpp",
        ".hpp",
        ".cc",
        ".cxx",
        ".cs",
        ".go",
        ".rs",
        ".rb",
        ".swift",
        ".m",
        ".mm",
        ".scala",
        ".lua",
        ".php",
        ".kt",
        ".kts",
        ".ttcn",
        ".ttcnpp",
        ".gd",
        ".zig",
    }
)


def _complexity_metrics(
    functions: list[dict], is_limited: bool
) -> tuple[dict, list[dict]]:
    values = [row["cc"] for row in functions]
    hotspots = sorted(
        (row for row in functions if row["cc"] > 10),
        key=lambda row: (-row["cc"], row["file"], row["line"]),
    )
    metrics: dict[str, object] = {"functions": len(functions), "hotspots": hotspots}
    if values or not is_limited:
        metrics.update(
            max_cc=max(values, default=0),
            average_cc=sum(values) / len(values) if values else 0.0,
        )
    return metrics, hotspots


def _hotspot_findings(hotspots: list[dict]) -> list[Finding]:
    findings = [
        Finding(
            rule="lizard.high-complexity",
            message=f"Function has cyclomatic complexity {row['cc']}",
            severity="high" if row["cc"] > 50 else "medium",
            path=row["file"],
            line=row["line"],
            symbol=row["function"],
        )
        for row in hotspots
    ]
    return findings


def analyze_complexity(ctx: ScanContext) -> StageResult:
    files = tuple(
        file
        for file in ctx.production_files
        if file.path.suffix.lower() in SUPPORTED_SUFFIXES
    )
    failure = partial(
        unavailable,
        _ID,
        "Function complexity",
        "complexity",
        "lizard",
        eligible_files=len(files),
    )
    if not files:
        return failure(
            reason="No production files supported by Lizard", status="unsupported"
        )
    result = ctx.run(
        [
            "lizard",
            "--xml",
            "--no-gitignore",
            "--ignore_warnings",
            "-1",
            "--",
            *(str(file.path) for file in files),
        ],
        cwd=ctx.scratch,
    )
    status = execution_status(result, (0,))
    if status is not None:
        return failure(
            reason="Lizard execution did not complete valid analysis", status=status
        )
    try:
        functions = observations(ctx, files, result.stdout)
    except (
        ET.ParseError,
        ValueError,
        TypeError,
        KeyError,
        OSError,
        UnicodeError,
        SyntaxError,
        RecursionError,
    ):
        return failure(
            reason="Lizard output failed schema or coverage validation", status="failed"
        )
    is_limited = any(file.path.suffix.lower() == ".scala" for file in files)
    metrics, hotspots = _complexity_metrics(functions, is_limited)
    return StageResult(
        _ID,
        "Function complexity",
        "complexity",
        "limited" if is_limited else "ok",
        "lizard",
        version=tool_version(ctx, "lizard"),
        metrics=metrics,
        findings=_hotspot_findings(hotspots),
        reason="Lizard may omit valid Scala function declarations; function coverage is incomplete"
        if is_limited
        else "",
        analyzed_files=len(files),
        eligible_files=len(files),
        duration_seconds=result.duration_seconds,
    )
