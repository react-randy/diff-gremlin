"""Collect bindings belonging to one Python lexical scope."""

import ast
from dataclasses import dataclass


class _Bindings(ast.NodeVisitor):
    """Collect bindings owned by one Python lexical scope."""

    def __init__(self):
        self.aliases = {}
        self.shadowed = set()

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self.shadowed.add(node.id)

    def visit_Import(self, node):
        self.aliases.update({item.asname or item.name: item.name for item in node.names})

    def visit_ImportFrom(self, node):
        self.aliases.update(
            {item.asname or item.name: f"{node.module}.{item.name}" for item in node.names}
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
    names = {arg.arg for arg in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)}
    names.update(arg.arg for arg in (arguments.vararg, arguments.kwarg) if arg is not None)
    return names
