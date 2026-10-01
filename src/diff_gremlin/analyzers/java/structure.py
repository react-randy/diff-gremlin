"""Produce Java syntax-tree evidence using only the installed JDK parser."""

import tempfile
from pathlib import Path

from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.analyzers.versions import tool_version

from diff_gremlin.analyzers.javascript.installed import trusted_executable
from diff_gremlin.analyzers.javascript.output import evidence, located_findings, natural
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult

_ID, _LABEL = "java.structure", "Java syntax and structure"


def analyze_java_structure(ctx: ScanContext) -> StageResult:
    files = tuple(file for file in ctx.production_files if file.language == "java")

    def absent(reason, status="missing"):
        return unavailable(
            _ID,
            _LABEL,
            "structure",
            "javac-parser",
            reason,
            status=status,
            eligible_files=len(files),
        )

    if not files:
        return absent("No Java production files", "skipped")
    compiler, java = trusted_executable(ctx, "javac"), trusted_executable(ctx, "java")
    if not compiler or not java:
        return absent("Installed trusted JDK compiler/parser unavailable")
    with tempfile.TemporaryDirectory(
        prefix="java-parser-", dir=ctx.scratch
    ) as directory:
        workspace = Path(directory)
        empty = workspace / "empty"
        empty.mkdir()
        asset = Path(__file__).parent / "assets" / "StructureProbe.java"
        build = ctx.run(
            [
                compiler,
                "-proc:none",
                "-implicit:none",
                "-classpath",
                str(empty),
                "-sourcepath",
                str(empty),
                "-d",
                str(workspace),
                str(asset),
            ],
            cwd=workspace,
        )
        if build.status != "ok" or build.returncode != 0:
            return absent(
                f"Shipped JDK parser driver compilation {build.status}; exit {build.returncode}",
                build.status if build.status in {"missing", "timeout"} else "failed",
            )
        result = ctx.run(
            [
                java,
                "-cp",
                str(workspace),
                "StructureProbe",
                *(str(f.path.resolve()) for f in files),
            ],
            cwd=workspace,
        )
        if result.status != "ok" or result.returncode != 0:
            return absent(
                f"JDK syntax parsing {result.status}; exit {result.returncode}",
                result.status if result.status in {"missing", "timeout"} else "failed",
            )
        try:
            data = evidence(result.stdout, files)
            if not all(
                natural(data.get(k))
                for k in ("type_count", "method_count", "error_count")
            ):
                raise ValueError("invalid structure counters")
            findings = located_findings(data["findings"], files)
        except (ValueError, TypeError):
            return absent(
                "JDK parser returned malformed or incomplete evidence", "failed"
            )
    return StageResult(
        _ID,
        _LABEL,
        "structure",
        "ok",
        "javac-parser",
        tool_version(ctx, compiler),
        metrics={k: data[k] for k in ("type_count", "method_count", "error_count")},
        findings=findings,
        reason="Syntax trees only; no dependency resolution or LSP diagnostics",
        analyzed_files=len(files),
        eligible_files=len(files),
        duration_seconds=result.duration_seconds + build.duration_seconds,
    )
