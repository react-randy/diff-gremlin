"""Measure production function cyclomatic complexity once with Lizard."""

import ast
import xml.etree.ElementTree as ET
from functools import partial

from diff_gremlin.analyzers.locations import relative_location
from diff_gremlin.analyzers.status import execution_status, unavailable
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext, SourceFile
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


def _values(item: ET.Element, length: int) -> list[int]:
    values = [int(value.text or "") for value in item.findall("value")]
    if len(values) != length or any(value < 0 for value in values):
        raise ValueError("invalid Lizard metric row")
    return values


def _functions(
    ctx: ScanContext, files: tuple[SourceFile, ...], measure: ET.Element
) -> list[dict]:
    observations = {}
    for item in measure.findall("item"):
        name, location = item.attrib["name"].rsplit(" at ", 1)
        path, line_text = location.rsplit(":", 1)
        path = relative_location(ctx.root, path, files)
        line = int(line_text)
        cc = _values(item, 3)[2]
        if line < 1 or cc < 1 or not name.endswith("(...)"):
            raise ValueError("invalid Lizard function location")
        name = name[:-5]
        identity = (path, line, name)
        if identity in observations:
            raise ValueError("duplicate Lizard function observation")
        observations[identity] = {
            "file": path,
            "function": name,
            "line": line,
            "cc": cc,
        }
    return sorted(
        observations.values(),
        key=lambda row: (row["file"], row["line"], row["function"]),
    )


def _observations(
    ctx: ScanContext, files: tuple[SourceFile, ...], text: str
) -> list[dict]:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("unsupported XML declaration")
    root = ET.fromstring(text)
    measures = root.findall("measure")
    if root.tag != "cppncss" or len(measures) != 2:
        raise ValueError("invalid Lizard root")
    function_measure = root.find("measure[@type='Function']")
    file_measure = root.find("measure[@type='File']")
    if function_measure is None or file_measure is None:
        raise ValueError("missing Lizard file or function measure")
    seen = {}
    for item in file_measure.findall("item"):
        path = relative_location(ctx.root, item.attrib.get("name"), files)
        if path in seen:
            raise ValueError("duplicate Lizard file observation")
        seen[path] = _values(item, 4)[3]
    if set(seen) != {file.relative_path for file in files}:
        raise ValueError("Lizard did not cover the eligible file inventory")
    functions = _functions(ctx, files, function_measure)
    for path, expected in seen.items():
        if sum(row["file"] == path for row in functions) != expected:
            raise ValueError("Lizard file count disagrees with function observations")
    for file in files:
        if file.path.suffix.lower() == ".py":
            tree = ast.parse(file.path.read_text(encoding="utf-8"))
            expected = sum(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                for node in ast.walk(tree)
            )
            if expected != seen[file.relative_path]:
                raise ValueError("Lizard missed Python function declarations")
    return functions


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
        functions = _observations(ctx, files, result.stdout)
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
    values = [row["cc"] for row in functions]
    hotspots = sorted(
        (row for row in functions if row["cc"] > 10),
        key=lambda row: (-row["cc"], row["file"], row["line"]),
    )
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
    is_limited = any(file.path.suffix.lower() == ".scala" for file in files)
    metrics: dict[str, object] = {"functions": len(functions), "hotspots": hotspots}
    if values or not is_limited:
        metrics.update(
            max_cc=max(values, default=0),
            average_cc=sum(values) / len(values) if values else 0.0,
        )
    return StageResult(
        _ID,
        "Function complexity",
        "complexity",
        "limited" if is_limited else "ok",
        "lizard",
        version=tool_version(ctx, "lizard"),
        metrics=metrics,
        findings=findings,
        reason="Lizard may omit valid Scala function declarations; function coverage is incomplete"
        if is_limited
        else "",
        analyzed_files=len(files),
        eligible_files=len(files),
        duration_seconds=result.duration_seconds,
    )
