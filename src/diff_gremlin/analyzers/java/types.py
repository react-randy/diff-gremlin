"""Collect standalone javac diagnostics without processors or target builds."""

import re
import tempfile
from functools import partial
from pathlib import Path

from diff_gremlin.analyzers.javascript.installed import trusted_executable
from diff_gremlin.analyzers.javascript.output import failure_status, valid_run
from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_ID, _LABEL = "java.types", "Java standalone static types"
_DIAGNOSTIC = re.compile(r"^(.+\.java):(\d+):(\d+): (compiler\.(?:err|warn)\.[a-z0-9.]+)")


def _invoke(ctx, compiler, files):
    with tempfile.TemporaryDirectory(prefix="java-types-", dir=ctx.scratch) as directory:
        workspace = Path(directory)
        empty = workspace / "empty"
        empty.mkdir()
        return ctx.run(
            [
                compiler,
                "-proc:none",
                "-implicit:none",
                "-encoding",
                "UTF-8",
                "-XDrawDiagnostics",
                "-classpath",
                str(empty),
                "-sourcepath",
                str(empty),
                "-d",
                str(workspace / "classes"),
                *(str(f.path.resolve()) for f in files),
            ],
            cwd=workspace,
        )


def _source_paths(files):
    paths = {str(f.path.resolve()): f.relative_path for f in files}
    # javac commonly emits just the basename despite absolute source argv.
    names = {
        f.path.name: f.relative_path
        for f in files
        if sum(g.path.name == f.path.name for g in files) == 1
    }
    return paths, names


def _diagnostic(line, paths, names):
    match = _DIAGNOSTIC.match(line)
    if not match:
        if (
            line.strip()
            and not re.fullmatch(r"\d+ (?:errors?|warnings?)", line.strip())
            and not line.startswith("compiler.note.")
        ):
            raise ValueError("unrecognized javac output")
        return None
    path, lineno, column, rule = match.groups()
    relative = paths.get(path) or names.get(path)
    if not relative:
        raise ValueError("javac diagnostic could not be tied to selected source")
    severity = "medium" if rule.startswith("compiler.err.") else "low"
    return Finding(
        rule,
        f"Review javac {rule} diagnostic",
        severity,
        relative,
        int(lineno),
        int(column),
    )


def _counts(findings):
    errors = sum(f.severity == "medium" for f in findings)
    warnings = sum(f.severity == "low" for f in findings)
    dependencies = sum(
        f.rule in {"compiler.err.doesnt.exist", "compiler.err.cant.access"} for f in findings
    )
    return errors, warnings, dependencies


def _diagnostics(result, files):
    paths, names = _source_paths(files)
    observations = (
        _diagnostic(line, paths, names) for line in (result.stdout + result.stderr).splitlines()
    )
    findings = [finding for finding in observations if finding is not None]
    errors, warnings, dependency_count = _counts(findings)
    if (result.returncode == 1 and not errors) or (result.returncode == 0 and errors):
        raise ValueError("javac exit/diagnostic evidence inconsistent")
    return findings, errors, warnings, dependency_count


def analyze_java_types(ctx: ScanContext) -> StageResult:
    files = tuple(file for file in ctx.production_files if file.language == "java")

    absent = partial(unavailable, _ID, _LABEL, "types", "javac", eligible_files=len(files))

    if not files:
        return absent("No Java production files", status="skipped")
    compiler = trusted_executable(ctx, "javac")
    if not compiler:
        return absent("Installed trusted javac unavailable; target builds are excluded")
    result = _invoke(ctx, compiler, files)
    if not valid_run(result, (0, 1)):
        return absent(
            f"Standalone javac invocation {result.status}; exit {result.returncode}",
            status=failure_status(result),
        )
    try:
        findings, errors, warnings, dependency_count = _diagnostics(result, files)
    except ValueError:
        return absent(
            "javac exit/diagnostic evidence inconsistent, unrecognized or outside selected source",
            status="failed",
        )
    limited = dependency_count > 0
    return StageResult(
        _ID,
        _LABEL,
        "types",
        "limited" if limited else "ok",
        "javac",
        tool_version(ctx, compiler),
        metrics={
            "error_count": errors,
            "warning_count": warnings,
            "dependency_count": dependency_count,
        },
        findings=findings,
        scope="standalone-static",
        reason="Standalone JDK types; project dependencies/build configuration excluded"
        + ("; external dependency diagnostics limit semantics" if limited else ""),
        eligible_files=len(files),
        analyzed_files=len(files),
        duration_seconds=result.duration_seconds,
    )
