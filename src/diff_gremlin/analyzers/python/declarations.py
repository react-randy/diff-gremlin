"""Account for Python ellipsis declarations omitted by the native function parser."""

import ast

from diff_gremlin.domain.context import SourceFile


def functions(node: ast.AST, owners: tuple[str, ...] = ()):
    """Yield each named function with its lexical class/function owner."""
    nested = owners
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        nested = (*owners, node.name)
        yield node, ".".join(nested)
    elif isinstance(node, ast.ClassDef):
        nested = (*owners, node.name)
    for child in ast.iter_child_nodes(node):
        yield from functions(child, nested)


def ellipsis_body(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Recognize a declaration body, allowing its optional documentation string."""
    body = node.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return (
        len(body) == 1
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and body[0].value.value is Ellipsis
    )


def missing_declarations(file: SourceFile, observed: list[dict]) -> list[dict]:
    """Reject missed executable bodies and account for branch-free declarations."""
    tree = ast.parse(file.path.read_text(encoding="utf-8"))
    declarations = list(functions(tree))
    rows = [row for row in observed if row["file"] == file.relative_path]
    lines = {row["line"] for row in rows}
    missing = [
        {
            "file": file.relative_path,
            "function": name,
            "line": node.lineno,
            "cc": 1,
            "origin": "python-ast-ellipsis-declaration",
        }
        for node, name in declarations
        if node.lineno not in lines and ellipsis_body(node)
    ]
    if len(rows) + len(missing) != len(declarations):
        raise ValueError("Lizard missed Python executable function declarations")
    return missing
