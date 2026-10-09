"""Measure production function cyclomatic complexity once with Lizard."""

import hashlib
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
from diff_gremlin.domain.stages import StageResult, StageStatus

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
            fingerprint=hashlib.sha256(
                f"lizard.high-complexity\0{row['file']}\0{row['function']}".encode(
                    "utf-8", "surrogateescape"
                )
            ).hexdigest()[:20],
            metric="cyclomatic_complexity",
            value=row["cc"],
            identity_kind="qualified",
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


def _result_status(status: StageStatus, reason: str, is_limited: bool) -> StageStatus:
    """Retain transport gaps separately from known language coverage limits."""
    if reason:
        return status
    return "limited" if is_limited else "ok"


def _analyze_complexity(
    ctx: ScanContext, files: tuple[SourceFile, ...], stage_id: str, label: str
) -> StageResult:
    failure = partial(
        unavailable,
        stage_id,
        label,
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
        stage_id,
        label,
        "complexity",
        _result_status(evidence.status, evidence.reason, is_limited),
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


def analyze_complexity(ctx: ScanContext) -> StageResult:
    """Measure non-PHP production files through the common validated Lizard adapter."""
    files = tuple(
        file
        for file in ctx.production_files
        if file.path.suffix.lower() in SUPPORTED_SUFFIXES
        and file.language not in {"php", "php-blade"}
    )
    return _analyze_complexity(ctx, files, _ID, "Function complexity")


def analyze_php_complexity(ctx: ScanContext) -> StageResult:
    """Keep PHP function evidence distinct and avoid measuring it twice."""
    files = tuple(file for file in ctx.production_files if file.language == "php")
    if not files:
        return unavailable(
            "complexity.php",
            "PHP function complexity",
            "complexity",
            "lizard",
            "No production PHP files",
            status="skipped",
            required=False,
        )
    result = _analyze_complexity(
        ctx, files, "complexity.php", "PHP function complexity"
    )
    if not result.reason:
        result.reason = "Lizard PHP function/method observations; nested closures can be included in their enclosing method; test paths and Pest.php are excluded"
    return result
