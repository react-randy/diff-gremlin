"""Coordinate language execution observations and Unicode correlation."""

from diff_gremlin.analyzers.java.execution import observe_java_calls
from diff_gremlin.analyzers.javascript.execution import observe_javascript_calls
from diff_gremlin.analyzers.python.execution import observe_python_calls
from diff_gremlin.analyzers.shell import shell_observations
from diff_gremlin.analyzers.unicode import analyze_unicode
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult


def _pairs(ctx, calls):
    suspicious = {
        f.path: f
        for f in analyze_unicode(ctx).findings
        if f.severity in {"medium", "high"}
    }
    return [
        Finding(
            "security.obfuscated-execution",
            f"Execution call shares file with {suspicious[call.path].symbol} at line {suspicious[call.path].line}; review both locations",
            "high",
            call.path,
            call.line,
            call.column,
            confidence="medium",
        )
        for call in calls
        if call.path in suspicious and call.severity in {"medium", "high"}
    ]


def _files(ctx, languages):
    return tuple(file for file in ctx.files if file.language in languages)


def _unsupported(ctx):
    supported = {
        "python",
        "javascript",
        "typescript",
        "java",
        "shell",
        "",
        "unknown",
        "text",
    }
    return sorted(
        {file.language for file in ctx.files if file.language not in supported}
    )


def _status(reasons, files):
    if reasons:
        return "limited"
    return "ok" if files else "skipped"


def analyze_execution(ctx: ScanContext) -> StageResult:
    observations = (
        observe_python_calls(_files(ctx, {"python"}), timeout=ctx.timeout),
        observe_javascript_calls(ctx, _files(ctx, {"javascript", "typescript"})),
        observe_java_calls(ctx, _files(ctx, {"java"})),
        shell_observations(ctx, _files(ctx, {"shell"})),
    )
    findings = [finding for rows, _, _ in observations for finding in rows]
    reasons = [reason for _, _, reason in observations if reason]
    findings.extend(_pairs(ctx, findings))
    unsupported = _unsupported(ctx)
    if unsupported:
        reasons.append("Call parsing unsupported for: " + ", ".join(unsupported))
    files = _files(ctx, {"python", "javascript", "typescript", "java", "shell"})
    return StageResult(
        "security.execution",
        "Execution-call observations",
        "security",
        _status(reasons, files),
        "builtin-ast/installed-parsers",
        metrics={
            "call_count": sum(
                f.rule != "security.obfuscated-execution" for f in findings
            ),
            "actionable_count": sum(
                f.severity in {"medium", "high", "critical"} for f in findings
            ),
            "unsupported_languages": unsupported,
        },
        findings=findings,
        reason="; ".join(reasons)
        if reasons
        else "Syntax observations with approximate lexical bindings; no flow, runtime reachability or authorship inference",
        scope="current-python-js-ts-java-shell",
        analyzed_files=sum(count for _, count, _ in observations),
        eligible_files=len(files),
    )
