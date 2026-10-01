"""Observe Python calls using lexical bindings and located AST nodes."""

import ast
import time

from diff_gremlin.analyzers.python.execution.bindings import (
    _Bindings,
    _parameters,
    _Scope,
)
from diff_gremlin.analyzers.python.execution.rules import _python_rule
from diff_gremlin.analyzers.python.execution.source import SourceLimit, parse_source
from diff_gremlin.domain.context import SourceFile
from diff_gremlin.domain.findings import Finding


class _PythonCalls(ast.NodeVisitor):
    """Resolve selected call names in their lexical owner, without execution."""

    def __init__(self, file, deadline):
        self.deadline = deadline
        self.file = file
        self.scopes = []
        self.findings = []

    def visit(self, node):
        if time.monotonic() >= self.deadline:
            raise TimeoutError("Python call observation time budget exhausted")
        return super().visit(node)

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

    def _visit_defaults(self, arguments):
        for expression in (*arguments.defaults, *arguments.kw_defaults):
            if expression is not None:
                self.visit(expression)

    def visit_FunctionDef(self, node):
        for expression in node.decorator_list:
            self.visit(expression)
        self._visit_defaults(node.args)
        self._scope(node.body, _parameters(node.args))

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        for expression in (
            *node.decorator_list,
            *node.bases,
            *(keyword.value for keyword in node.keywords),
        ):
            self.visit(expression)
        self._scope(node.body, is_class=True)

    def visit_Lambda(self, node):
        self._visit_defaults(node.args)
        self._scope([node.body], _parameters(node.args))

    def _comprehension(self, node):
        bindings = _Bindings()
        for generator in node.generators:
            bindings.visit(generator.target)
        self.visit(node.generators[0].iter)
        self.scopes.append(_Scope(bindings))
        for index, generator in enumerate(node.generators):
            if index:
                self.visit(generator.iter)
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


def _python_calls(file: SourceFile, deadline: float) -> list[Finding]:
    tree = parse_source(file, deadline)
    observer = _PythonCalls(file, deadline)
    observer.visit(tree)
    return observer.findings


def observe_python_calls(
    files: tuple[SourceFile, ...], *, timeout: float = 120.0
) -> tuple[list[Finding], int, str]:
    """Return observations, analyzed count and limitations for inventoried Python files."""
    findings, reasons = [], []
    analyzed = 0
    deadline = time.monotonic() + timeout
    for index, file in enumerate(files):
        if time.monotonic() >= deadline:
            reasons.append(
                f"Python call parsing time budget exhausted; omitted {len(files) - index} eligible files"
            )
            break
        try:
            findings.extend(_python_calls(file, deadline))
            analyzed += 1
        except SourceLimit as error:
            reasons.append(f"{error}: {file.relative_path}")
        except TimeoutError:
            reasons.append(
                f"Python call parsing time budget exhausted; omitted {len(files) - index} eligible files"
            )
            break
        except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
            reasons.append(f"Python syntax/read unavailable: {file.relative_path}")
    return findings, analyzed, "; ".join(reasons)
