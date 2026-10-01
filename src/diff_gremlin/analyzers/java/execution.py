"""Project Java structure evidence into selected execution observations."""

from dataclasses import replace

from diff_gremlin.analyzers.java.structure import analyze_java_structure
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding

_JAVA_EXECUTION = {
    "java.runtime-exec",
    "java.script-eval",
    "java.process-builder",
    "java.shell-execution",
    "java.unsafe-api",
    "java.reflective-load",
    "java.reflective-access",
    "java.script-engine",
}


def observe_java_calls(
    ctx: ScanContext, files: tuple[SourceFile, ...]
) -> tuple[list[Finding], int, str]:
    """Keep Java execution findings and propagate parser coverage limitations."""
    if not files:
        return [], 0, ""
    result = analyze_java_structure(replace(ctx, production_files=files))
    findings = [f for f in result.findings if f.rule in _JAVA_EXECUTION]
    reason = (
        "Java parsing limited: " + result.reason
        if result.status != "ok" or result.metrics.get("error_count")
        else ""
    )
    return findings, result.analyzed_files, reason
