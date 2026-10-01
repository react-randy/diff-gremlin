"""Compute explicitly named Python AST decision complexity for Git history."""

import ast


def _decision_increment(node: ast.AST) -> int:
    if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler)):
        return 1
    if isinstance(node, ast.BoolOp):
        return len(node.values) - 1
    if isinstance(node, ast.comprehension):
        return 1 + len(node.ifs)
    if isinstance(node, ast.match_case):
        # A final wildcard case is the default branch, rather than another decision.
        return int(
            not (isinstance(node.pattern, ast.MatchAs) and node.pattern.pattern is None)
        ) + int(node.guard is not None)
    return 0


def _function_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    score = 1
    pending: list[ast.AST] = list(node.body)
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        score += _decision_increment(child)
        pending.extend(ast.iter_child_nodes(child))
    return score


def source_observations(text: str) -> list[int]:
    if "\ufffd" in text:
        raise ValueError("undecodable Python source")
    tree = ast.parse(text)
    return [
        _function_complexity(node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def commit_observations(sha: str, timestamp: int, contents: list[str]) -> dict:
    values = []
    analyzed = 0
    for text in contents:
        values.extend(source_observations(text))
        analyzed += 1
    return {
        "commit": sha,
        "timestamp": timestamp,
        "files": analyzed,
        "functions": len(values),
        "average_cc": sum(values) / len(values) if values else 0.0,
        "max_cc": max(values, default=0),
    }
