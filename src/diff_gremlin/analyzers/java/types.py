"""Collect standalone javac diagnostics without processors or target builds."""

import re
import tempfile
from pathlib import Path

from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.analyzers.versions import tool_version

from diff_gremlin.analyzers.javascript.installed import trusted_executable
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_ID, _LABEL = "java.types", "Java standalone static types"
_DIAGNOSTIC = re.compile(
    r"^(.+\.java):(\d+):(\d+): (compiler\.(?:err|warn)\.[a-z0-9.]+)"
)


def analyze_java_types(ctx: ScanContext) -> StageResult:
    files = tuple(file for file in ctx.production_files if file.language == "java")

    def absent(reason, status="missing"):
        return unavailable(
            _ID,
            _LABEL,
            "types",
            "javac",
            reason,
            status=status,
            eligible_files=len(files),
        )

    if not files:
        return absent("No Java production files", "skipped")
    compiler = trusted_executable(ctx, "javac")
    if not compiler:
        return absent("Installed trusted javac unavailable; target builds are excluded")
    with tempfile.TemporaryDirectory(
        prefix="java-types-", dir=ctx.scratch
    ) as directory:
        workspace = Path(directory)
        empty = workspace / "empty"
        empty.mkdir()
        result = ctx.run(
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
        if result.status != "ok" or result.returncode not in {0, 1}:
            return absent(
                f"Standalone javac invocation {result.status}; exit {result.returncode}",
                result.status if result.status in {"missing", "timeout"} else "failed",
            )
        paths = {str(f.path.resolve()): f.relative_path for f in files}
        # javac commonly emits just the basename despite absolute source argv.
        names = {
            f.path.name: f.relative_path
            for f in files
            if sum(g.path.name == f.path.name for g in files) == 1
        }
        findings = []
        dependency_count = 0
        unexpected = False
        for line in (result.stdout + result.stderr).splitlines():
            match = _DIAGNOSTIC.match(line)
            if not match:
                if (
                    line.strip()
                    and not re.fullmatch(r"\d+ (?:errors?|warnings?)", line.strip())
                    and not line.startswith("compiler.note.")
                ):
                    unexpected = True
                continue
            path, lineno, column, rule = match.groups()
            relative = paths.get(path) or names.get(path)
            if not relative:
                return absent(
                    "javac diagnostic could not be tied to selected source", "failed"
                )
            severity = "medium" if rule.startswith("compiler.err.") else "low"
            findings.append(
                Finding(
                    rule,
                    f"Review javac {rule} diagnostic",
                    severity,
                    relative,
                    int(lineno),
                    int(column),
                )
            )
            dependency_count += rule in {
                "compiler.err.doesnt.exist",
                "compiler.err.cant.access",
            }
        errors = sum(f.severity == "medium" for f in findings)
        warnings = sum(f.severity == "low" for f in findings)
        if (
            unexpected
            or (result.returncode == 1 and not errors)
            or (result.returncode == 0 and errors)
        ):
            return absent(
                "javac exit/diagnostic evidence inconsistent or unrecognized", "failed"
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
