"""Walk validated nodes, with explicit ownership for nested functions."""

from collections.abc import Iterator


def children(node: dict) -> Iterator[dict]:
    """Yield immediate AST children, excluding position and scalar metadata."""
    for value in node.values():
        if isinstance(value, dict) and "_kind" in value:
            yield value
        elif isinstance(value, list):
            yield from (
                item for item in value if isinstance(item, dict) and "_kind" in item
            )


def walk(node: dict, *, exclude_functions: bool = False) -> Iterator[dict]:
    """Visit each tree node once; optionally stop at nested function declarations."""
    pending = [node]
    while pending:
        current = pending.pop()
        if exclude_functions and current["_kind"] == "FuncDecl":
            continue
        yield current
        pending.extend(reversed(tuple(children(current))))
