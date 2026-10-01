"""Measure every JS/TS function code path using native ESLint complexity."""

from functools import partial
from pathlib import Path

from diff_gremlin.analyzers.javascript.installed import (
    installed_package,
    package_version,
    sibling_package,
    trusted_executable,
)
from diff_gremlin.analyzers.javascript.output import (
    evidence,
    failure_status,
    natural,
    positive,
    valid_run,
)
from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_ID, _LABEL = "complexity.javascript", "JavaScript/TypeScript function complexity"


def _environment(ctx):
    package = installed_package(ctx, "eslint", "eslint")
    node = trusted_executable(ctx, "node")
    parser = sibling_package(package, "@typescript-eslint/parser") if package else None
    if node is None or package is None or parser is None:
        return None
    return node, package, parser


def _function(row, paths):
    if not isinstance(row, dict) or row.get("path") not in paths:
        raise ValueError("function outside selected inventory")
    if not all(positive(row.get(key)) for key in ("line", "column", "cc")):
        raise ValueError("invalid function location or complexity")
    if row.get("kind") not in {
        "function",
        "class-field-initializer",
        "class-static-block",
    }:
        raise ValueError("invalid complexity code-path origin")
    line, column, kind = row["line"], row["column"], row["kind"]
    return {
        "file": paths[row["path"]],
        "line": line,
        "column": column,
        "cc": row["cc"],
        "function": f"{kind}@{line}:{column}",
        "kind": kind,
    }


def _observations(stdout, files):
    data = evidence(stdout, files)
    if not natural(data.get("parse_errors")) or not natural(data.get("expected_count")):
        raise ValueError("invalid complexity coverage counters")
    if not isinstance(data.get("functions"), list):
        raise TypeError("missing per-function observations")
    paths = {str(file.path.resolve()): file.relative_path for file in files}
    functions = [_function(row, paths) for row in data["functions"]]
    if len(functions) != data["expected_count"]:
        raise ValueError("native complexity omitted a code path")
    locations = {(row["file"], row["line"], row["column"], row["kind"]) for row in functions}
    if len(locations) != len(functions):
        raise ValueError("duplicate complexity identity")
    return functions, data["parse_errors"]


def _metrics(functions):
    values = [row["cc"] for row in functions]
    hotspots = sorted(
        (row for row in functions if row["cc"] > 10),
        key=lambda row: (-row["cc"], row["file"], row["line"], row["column"]),
    )
    return {
        "max_cc": max(values, default=0),
        "average_cc": sum(values) / len(values) if values else 0.0,
        "functions": len(functions),
        "hotspots": hotspots,
        "function_observations": functions,
    }


def _findings(hotspots):
    return [
        Finding(
            "eslint.high-complexity",
            f"Function code path has cyclomatic complexity {row['cc']}",
            "high" if row["cc"] > 50 else "medium",
            row["file"],
            row["line"],
            row["column"],
            symbol=row["function"],
        )
        for row in hotspots
    ]


def analyze_js_complexity(ctx: ScanContext) -> StageResult:
    files = tuple(
        file for file in ctx.production_files if file.language in {"javascript", "typescript"}
    )

    absent = partial(unavailable, _ID, _LABEL, "complexity", "eslint", eligible_files=len(files))

    if not files:
        return absent("No JavaScript or TypeScript production files", status="skipped")
    environment = _environment(ctx)
    if environment is None:
        return absent("Installed trusted Node/ESLint/parser dependencies unavailable")
    node, package, parser = environment
    result = ctx.run(
        [
            node,
            str(Path(__file__).parent / "assets" / "complexity.cjs"),
            str(package),
            str(parser),
            *(str(file.path.resolve()) for file in files),
        ],
        cwd=ctx.scratch,
    )
    if not valid_run(result):
        return absent(
            f"Controlled ESLint complexity invocation {result.status}; exit {result.returncode}",
            status=failure_status(result),
        )
    try:
        functions, parse_errors = _observations(result.stdout, files)
    except (ValueError, TypeError):
        return absent(
            "Native ESLint complexity failed schema or code-path coverage validation",
            status="failed",
        )
    if parse_errors:
        return absent(
            "JS/TS syntax errors prevent complete function complexity evidence",
            status="limited",
        )
    metrics = _metrics(functions)
    return StageResult(
        _ID,
        _LABEL,
        "complexity",
        "ok",
        "eslint",
        package_version(package),
        metrics=metrics,
        findings=_findings(metrics["hotspots"]),
        reason="Native ESLint classic complexity for functions and implicit class field/static-block code paths; separate coverage count; target configuration disabled",
        eligible_files=len(files),
        analyzed_files=len(files),
        duration_seconds=result.duration_seconds,
    )
