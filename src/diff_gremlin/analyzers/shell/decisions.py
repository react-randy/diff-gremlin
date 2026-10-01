"""Versioned Shell AST decision estimates; never claim exact runtime paths."""

from diff_gremlin.analyzers.shell.walk import walk

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


def function_rows(tree: dict, path: str) -> list[dict]:
    """Measure each named function while excluding nested function bodies."""
    rows = []
    for node in walk(tree):
        if node["_kind"] != "FuncDecl":
            continue
        rows.append(
            {
                "file": path,
                "function": node["Name"]["Value"],
                "line": node["Pos"]["Line"],
                "cc": 1
                + sum(
                    decision_count(child) for child in walk(node["Body"], exclude_functions=True)
                ),
            }
        )
    return rows
