"""Measure production function cyclomatic complexity once with Lizard."""

import time
import xml.etree.ElementTree as ET
from dataclasses import replace
from functools import partial

from diff_gremlin.analyzers.batches import collect_batches
from diff_gremlin.analyzers.complexity_output import observations
from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.process import RunResult
from diff_gremlin.domain.stages import StageResult

_ID = "complexity.lizard"
SUPPORTED_SUFFIXES = frozenset(
    {
        ".py",
        ".java",
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
    declarations = [
        row
        for row in functions
        if row.get("origin") == "python-ast-ellipsis-declaration"
    ]
    if declarations:
        metrics["declarations"] = declarations
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


def _coverage_reason(is_limited: bool, metrics: dict) -> str:
    if is_limited:
        return "Lizard may omit valid Scala function declarations; function coverage is incomplete"
    if metrics.get("declarations"):
        return "Python ellipsis declarations omitted by Lizard are accounted for with AST, named locations and branch-free complexity 1"
    return ""


def _validated_batch(
    ctx: ScanContext, files: tuple[SourceFile, ...], result: RunResult
) -> list[dict]:
    try:
        return observations(ctx, files, result.stdout)
    except (
        ET.ParseError,
        KeyError,
        OSError,
        UnicodeError,
        SyntaxError,
        RecursionError,
    ) as error:
        raise ValueError("invalid Lizard observations") from error


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
    started = time.monotonic()
    evidence = collect_batches(
        ctx,
        files,
        ["lizard", "--xml", "--no-gitignore", "--ignore_warnings", "-1"],
        (0,),
        partial(_validated_batch, ctx),
    )
    functions = evidence.values
    is_limited = any(file.path.suffix.lower() == ".scala" for file in files)
    metrics, hotspots = _complexity_metrics(
        functions, is_limited or bool(evidence.reason)
    )
    return StageResult(
        _ID,
        "Function complexity",
        "complexity",
        evidence.status if evidence.reason else "limited" if is_limited else "ok",
        "lizard",
        version=(
            tool_version(replace(ctx, timeout=evidence.remaining_time()), "lizard")
            if evidence.remaining_time() > 0
            else ""
        ),
        metrics=metrics if evidence.analyzed else {},
        findings=_hotspot_findings(hotspots),
        reason=(
            f"Lizard {evidence.reason}"
            if evidence.reason
            else _coverage_reason(is_limited, metrics)
        ),
        analyzed_files=evidence.analyzed,
        eligible_files=len(files),
        duration_seconds=time.monotonic() - started,
    )
