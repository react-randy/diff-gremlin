"""Adapt validated Shell syntax and function decisions to stage evidence."""

import hashlib

from diff_gremlin.analyzers.shell.decisions import MEASURE
from diff_gremlin.analyzers.shell.parser import Parsed, parse_files
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import Category, StageResult


def shell_files(files: tuple[SourceFile, ...]) -> tuple[SourceFile, ...]:
    """Keep the existing inventory's Shell eligibility explicit."""
    return tuple(file for file in files if file.language == "shell")


def stage(
    ctx: ScanContext,
    files: tuple[SourceFile, ...],
    parsed: Parsed,
    stage_id: str,
    label: str,
    category: Category,
) -> StageResult:
    """Carry truthful provenance, coverage and safe diagnostic observations."""
    return StageResult(
        stage_id,
        label,
        category,
        parsed.status,
        "shfmt",
        version=parsed.version,
        findings=list(parsed.findings),
        reason="; ".join(parsed.reasons),
        analyzed_files=parsed.analyzed,
        eligible_files=len(files),
        duration_seconds=parsed.duration,
    )


def analyze_shell_syntax(ctx: ScanContext) -> StageResult:
    """Parse all inventoried Shell files using the declared supported dialect."""
    files = shell_files(ctx.files)
    parsed = parse_files(ctx, files)
    result = stage(
        ctx, files, parsed, "shell.syntax.shfmt", "Shell syntax", "structure"
    )
    result.scope = "all-inventoried-shell"
    if parsed.analyzed:
        result.metrics = {
            "syntax_version": "shfmt-json-3.14.1",
            "syntax_errors": len(parsed.findings),
        }
    return result


def complexity_metrics(rows: list[dict]) -> tuple[dict[str, object], list[dict]]:
    """Expose the shared hotspot policy without changing its independent threshold."""
    hotspots = sorted(
        (row for row in rows if row["cc"] > 10),
        key=lambda row: (-row["cc"], row["file"], row["line"]),
    )
    values = [row["cc"] for row in rows]
    return {
        "measure": MEASURE,
        "functions": len(rows),
        "hotspots": hotspots,
        "max_cc": max(values, default=0),
        "average_cc": sum(values) / len(values) if values else 0.0,
        "function_rows": rows,
    }, hotspots


def hotspot_findings(hotspots: list[dict]) -> list[Finding]:
    """Locate decision estimates exceeding the existing maximum of ten."""
    return [
        Finding(
            "shell.high-complexity",
            f"Function has AST decision complexity {row['cc']}",
            "high" if row["cc"] > 50 else "medium",
            row["file"],
            row["line"],
            symbol=row["function"],
            fingerprint=hashlib.sha256(
                f"shell.high-complexity\0{row['file']}\0{row['function']}\0{MEASURE}".encode(
                    "utf-8", "surrogateescape"
                )
            ).hexdigest()[:20],
            metric=MEASURE,
            value=row["cc"],
            identity_kind="qualified",
        )
        for row in hotspots
    ]


def analyze_shell_complexity(ctx: ScanContext) -> StageResult:
    """Measure only production Shell functions; retain partial-file coverage."""
    files = shell_files(ctx.production_files)
    parsed = parse_files(ctx, files)
    result = stage(
        ctx, files, parsed, "complexity.shell", "Shell function decisions", "complexity"
    )
    if parsed.analyzed:
        rows = parsed.functions
        result.metrics, hotspots = complexity_metrics(rows)
        result.findings.extend(hotspot_findings(hotspots))
    return result


def shell_observations(
    ctx: ScanContext, files: tuple[SourceFile, ...]
) -> tuple[list[Finding], int, str]:
    """Supply calls and failure reasons to the existing security stage."""
    if not files:
        return [], 0, ""
    parsed = parse_files(ctx, files)
    findings = list(parsed.findings)
    findings.extend(parsed.calls)
    return findings, parsed.analyzed, "; ".join(parsed.reasons)
