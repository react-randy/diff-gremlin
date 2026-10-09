"""Versioned Shell AST decision estimates; never claim exact runtime paths."""

from collections.abc import Iterator

from diff_gremlin.analyzers.shell.walk import children, walk

MEASURE = "shell-ast-decision-complexity-v1"


def decision_count(node: dict) -> int:
    """Apply the frozen v1 case-arm and Boolean-expression convention."""
    kind = node["_kind"]
    if kind == "IfClause":
        return int(bool(node.get("Cond")))
    if kind in {"ForClause", "WhileClause"}:
        return 1
    if kind == "CaseClause":
        return max(0, len(node.get("Items", [])) - 1)
    if kind in {"BinaryCmd", "BinaryTest"}:
        return int(node["Op"] in {"&&", "||"})
    return 0


def named_functions(tree: dict) -> Iterator[tuple[dict, str]]:
    """Retain lexical owners without coupling identity to source positions."""
    pending: list[tuple[dict, tuple[str, ...]]] = [(tree, ())]
    while pending:
        node, owners = pending.pop()
        if node["_kind"] == "FuncDecl":
            owners = (*owners, node["Name"]["Value"])
            yield node, ".".join(
                name.replace("\\", "\\\\").replace(".", "\\.") for name in owners
            )
        pending.extend((child, owners) for child in reversed(tuple(children(node))))


def function_rows(tree: dict, path: str) -> list[dict]:
    """Measure each named function while excluding nested function bodies."""
    rows = []
    for node, name in named_functions(tree):
        rows.append(
            {
                "file": path,
                "function": name,
                "line": node["Pos"]["Line"],
                "cc": 1
                + sum(
                    decision_count(child)
                    for child in walk(node["Body"], exclude_functions=True)
                ),
            }
        )
    return rows
