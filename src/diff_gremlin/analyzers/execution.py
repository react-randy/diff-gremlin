"""Observe execution-call syntax with approximate lexical bindings."""

import ast
from dataclasses import dataclass, replace
from pathlib import Path

from diff_gremlin.analyzers.java.structure import analyze_java_structure
from diff_gremlin.analyzers.javascript.installed import (
    installed_package,
    trusted_executable,
)
from diff_gremlin.analyzers.javascript.output import (
    evidence,
    located_findings,
    natural,
    valid_run,
)
from diff_gremlin.analyzers.unicode import analyze_unicode
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_PYTHON_DYNAMIC = {
    "eval": "python.eval",
    "builtins.eval": "python.eval",
    "exec": "python.exec",
    "builtins.exec": "python.exec",
}
_PYTHON_PROCESS = {
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
}
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


class _Bindings(ast.NodeVisitor):
    """Collect bindings owned by one Python lexical scope."""

    def __init__(self):
        self.aliases = {}
        self.shadowed = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self.shadowed.add(node.id)

    def visit_Import(self, node):
        self.aliases.update(
            {item.asname or item.name: item.name for item in node.names}
        )

    def visit_ImportFrom(self, node):
        self.aliases.update(
            {
                item.asname or item.name: f"{node.module}.{item.name}"
                for item in node.names
            }
        )

    def visit_FunctionDef(self, node):
        self.shadowed.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_ClassDef = visit_FunctionDef

    def visit_Lambda(self, node):
        return None

    visit_ListComp = visit_Lambda
    visit_SetComp = visit_Lambda
    visit_DictComp = visit_Lambda
    visit_GeneratorExp = visit_Lambda


@dataclass
class _Scope:
    bindings: _Bindings
    is_class: bool = False


def _parameters(arguments):
    names = {
        arg.arg
        for arg in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
    }
    names.update(
        arg.arg for arg in (arguments.vararg, arguments.kwarg) if arg is not None
    )
    return names


def _process_rule(node: ast.Call, name: str):
    shell = next(
        (keyword.value for keyword in node.keywords if keyword.arg == "shell"), None
    )
    if name.endswith(("getoutput", "getstatusoutput")):
        return "python.shell-execution", "high"
    if shell is not None and not (
        isinstance(shell, ast.Constant) and shell.value is False
    ):
        return "python.shell-execution", "high"
    return "python.process-call", "info"


def _python_rule(node: ast.Call, name: str):
    if name in _PYTHON_DYNAMIC:
        return _PYTHON_DYNAMIC[name], "high"
    if name in {"compile", "builtins.compile"}:
        return "python.dynamic-compile", "info"
    if name in {"os.system", "os.popen"}:
        return "python.shell-execution", "high"
    return _process_rule(node, name) if name in _PYTHON_PROCESS else None


class _PythonCalls(ast.NodeVisitor):
    """Resolve selected call names in their lexical owner, without execution."""

    def __init__(self, file):
        self.file = file
        self.scopes = []
        self.findings = []

    def _scope(self, body, parameters=(), is_class=False):
        bindings = _Bindings()
        for node in body:
            bindings.visit(node)
        bindings.shadowed.update(parameters)
        self.scopes.append(_Scope(bindings, is_class))
        for node in body:
            self.visit(node)
        self.scopes.pop()

    def _resolve(self, name):
        for scope in reversed(self.scopes):
            if scope.is_class and scope is not self.scopes[-1]:
                continue
            if name in scope.bindings.shadowed:
                return ""
            if name in scope.bindings.aliases:
                return scope.bindings.aliases[name]
        return name

    def _name(self, node):
        if isinstance(node, ast.Name):
            return self._resolve(node.id)
        if isinstance(node, ast.Attribute):
            return f"{self._name(node.value)}.{node.attr}"
        return ""

    def visit_Module(self, node):
        self._scope(node.body)

    def visit_FunctionDef(self, node):
        for expression in (
            *node.decorator_list,
            *node.args.defaults,
            *node.args.kw_defaults,
        ):
            if expression is not None:
                self.visit(expression)
        self._scope(node.body, _parameters(node.args))

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        for expression in (*node.decorator_list, *node.bases):
            self.visit(expression)
        self._scope(node.body, is_class=True)

    def visit_Lambda(self, node):
        self._scope([node.body], _parameters(node.args))

    def _comprehension(self, node):
        bindings = _Bindings()
        for generator in node.generators:
            self.visit(generator.iter)
            bindings.visit(generator.target)
        self.scopes.append(_Scope(bindings))
        for generator in node.generators:
            for condition in generator.ifs:
                self.visit(condition)
        expressions = (
            (node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)
        )
        for expression in expressions:
            self.visit(expression)
        self.scopes.pop()

    visit_ListComp = _comprehension
    visit_SetComp = _comprehension
    visit_DictComp = _comprehension
    visit_GeneratorExp = _comprehension

    def visit_Call(self, node):
        name = self._name(node.func)
        observation = _python_rule(node, name)
        if observation:
            rule, severity = observation
            self.findings.append(
                Finding(
                    rule,
                    f"Review {rule} call; syntax does not establish malicious intent",
                    severity,
                    self.file.relative_path,
                    node.lineno,
                    node.col_offset + 1,
                    symbol=name,
                    confidence="medium",
                )
            )
        self.generic_visit(node)


def _python_calls(file: SourceFile) -> list[Finding]:
    tree = ast.parse(file.path.read_text(encoding="utf-8"))
    observer = _PythonCalls(file)
    observer.visit(tree)
    return observer.findings


def _python_observations(files):
    findings, reasons = [], []
    analyzed = 0
    for file in files:
        if file.size_bytes > 1024 * 1024:
            reasons.append(f"Python call parsing size limit: {file.relative_path}")
            continue
        try:
            findings.extend(_python_calls(file))
            analyzed += 1
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
            reasons.append(f"Python syntax/read unavailable: {file.relative_path}")
    return findings, analyzed, "; ".join(reasons)


def _javascript_calls(ctx, files):
    if not files:
        return [], 0, ""
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
    if not valid_run(result):
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


def _java_observations(ctx, files):
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
    supported = {"python", "javascript", "typescript", "java", "", "unknown", "text"}
    return sorted(
        {file.language for file in ctx.files if file.language not in supported}
    )


def _status(reasons, files):
    if reasons:
        return "limited"
    return "ok" if files else "skipped"


def analyze_execution(ctx: ScanContext) -> StageResult:
    observations = (
        _python_observations(_files(ctx, {"python"})),
        _javascript_calls(ctx, _files(ctx, {"javascript", "typescript"})),
        _java_observations(ctx, _files(ctx, {"java"})),
    )
    findings = [finding for rows, _, _ in observations for finding in rows]
    reasons = [reason for _, _, reason in observations if reason]
    findings.extend(_pairs(ctx, findings))
    unsupported = _unsupported(ctx)
    if unsupported:
        reasons.append("Call parsing unsupported for: " + ", ".join(unsupported))
    files = _files(ctx, {"python", "javascript", "typescript", "java"})
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
        scope="current-python-js-ts-java",
        analyzed_files=sum(count for _, count, _ in observations),
        eligible_files=len(files),
    )
