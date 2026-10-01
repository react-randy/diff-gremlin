"""Observe actual execution-call syntax without running reviewed source."""

import ast
from dataclasses import replace
from pathlib import Path

from diff_gremlin.analyzers.java.structure import analyze_java_structure
from diff_gremlin.analyzers.javascript.installed import (
    installed_package,
    trusted_executable,
)
from diff_gremlin.analyzers.javascript.output import evidence, located_findings, natural
from diff_gremlin.analyzers.unicode import analyze_unicode
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult


def _name(node: ast.expr, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        return f"{_name(node.value, aliases)}.{node.attr}"
    return ""


def _python_calls(file: SourceFile) -> list[Finding]:
    tree = ast.parse(file.path.read_text(encoding="utf-8"))
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update({item.asname or item.name: item.name for item in node.names})
        elif isinstance(node, ast.ImportFrom):
            aliases.update(
                {
                    item.asname or item.name: f"{node.module}.{item.name}"
                    for item in node.names
                }
            )
    shadowed = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }
    shadowed.update(
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    shadowed.update(node.arg for node in ast.walk(tree) if isinstance(node, ast.arg))
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        root = node.func
        while isinstance(root, ast.Attribute):
            root = root.value
        if isinstance(root, ast.Name) and root.id in shadowed:
            continue
        name = _name(node.func, aliases)
        rule, severity = "", "high"
        if name in {"eval", "builtins.eval", "exec", "builtins.exec"}:
            rule = f"python.{name.split('.')[-1]}"
        elif name in {"compile", "builtins.compile"}:
            rule, severity = "python.dynamic-compile", "info"
        elif name in {"os.system", "os.popen"}:
            rule = "python.shell-execution"
        elif name in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
        }:
            shell = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "shell"),
                None,
            )
            risky = name.endswith(("getoutput", "getstatusoutput")) or (
                shell is not None
                and not (isinstance(shell, ast.Constant) and shell.value is False)
            )
            rule, severity = (
                ("python.shell-execution", "high")
                if risky
                else ("python.process-call", "info")
            )
        if rule:
            findings.append(
                Finding(
                    rule,
                    f"Review {rule} call; execution syntax alone does not establish malicious intent",
                    severity,
                    file.relative_path,
                    node.lineno,
                    node.col_offset + 1,
                    symbol=name,
                    confidence="medium",
                )
            )
    return findings


def _javascript_calls(
    ctx: ScanContext, files: tuple[SourceFile, ...]
) -> tuple[list[Finding], int, str]:
    package, node = (
        installed_package(ctx, "tsc", "typescript"),
        trusted_executable(ctx, "node"),
    )
    if not package or not node:
        return [], 0, "Trusted TypeScript syntax parser unavailable for JS/TS calls"
    asset = Path(__file__).parent / "javascript" / "assets" / "execution.cjs"
    result = ctx.run(
        [node, str(asset), str(package), *(str(file.path.resolve()) for file in files)],
        cwd=ctx.scratch,
    )
    if result.status != "ok" or result.returncode != 0:
        return [], 0, f"JS/TS syntax parser {result.status}; exit {result.returncode}"
    try:
        data = evidence(result.stdout, files)
        if not natural(data.get("parse_errors")):
            raise ValueError("invalid parse error count")
        return (
            located_findings(data["findings"], files),
            len(files),
            "JS/TS syntax errors limit calls" if data["parse_errors"] else "",
        )
    except (ValueError, TypeError):
        return [], 0, "JS/TS parser output malformed or incomplete"


def _pairs(ctx: ScanContext, calls: list[Finding]) -> list[Finding]:
    controls = analyze_unicode(ctx).findings
    suspicious = {f.path: f for f in controls if f.severity in {"medium", "high"}}
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


def analyze_execution(ctx: ScanContext) -> StageResult:
    files = tuple(
        file
        for file in ctx.files
        if file.language in {"python", "javascript", "typescript", "java"}
    )
    findings, reasons = [], []
    analyzed = 0
    for file in files:
        if file.language != "python":
            continue
        if file.size_bytes > 1024 * 1024:
            reasons.append(f"Python call parsing size limit: {file.relative_path}")
            continue
        try:
            findings.extend(_python_calls(file))
            analyzed += 1
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
            reasons.append(f"Python syntax/read unavailable: {file.relative_path}")
    javascript = tuple(
        file for file in files if file.language in {"javascript", "typescript"}
    )
    if javascript:
        calls, count, reason = _javascript_calls(ctx, javascript)
        findings.extend(calls)
        analyzed += count
        if reason:
            reasons.append(reason)
    java = tuple(file for file in files if file.language == "java")
    if java:
        result = analyze_java_structure(replace(ctx, production_files=java))
        findings.extend(
            f
            for f in result.findings
            if f.rule
            in {"java.runtime-exec", "java.script-eval", "java.process-builder"}
        )
        analyzed += result.analyzed_files
        if result.status != "ok" or result.metrics.get("error_count"):
            reasons.append("Java parsing limited: " + result.reason)
    findings.extend(_pairs(ctx, findings))
    unsupported = sorted(
        {
            file.language
            for file in ctx.files
            if file.language
            not in {"python", "javascript", "typescript", "java", "", "unknown", "text"}
        }
    )
    if unsupported:
        reasons.append("Call parsing unsupported for: " + ", ".join(unsupported))
    return StageResult(
        "security.execution",
        "Execution-call observations",
        "security",
        "limited" if reasons else ("ok" if files else "skipped"),
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
        else "Syntax-based call observations; no runtime reachability or authorship inference",
        scope="current-python-js-ts-java",
        analyzed_files=analyzed,
        eligible_files=len(files),
    )
