"""Validate the v3.14.1 JSON shape before any evidence is consumed.

The declarative asset derives from syntax/nodes.go at upstream commit
a3f0c75d21d918756fa38de8b5d3429efde7948b; see assets/SHFMT-LICENSE.
Concrete structs omit Type; interface children require it.
"""

import json
from bisect import bisect_right
from pathlib import Path

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_NODES = 20_000
MAX_DEPTH = 128
_SCHEMA = json.loads((Path(__file__).parent / "assets" / "schema.json").read_text())
_OPERATORS = json.loads(
    (Path(__file__).parent / "assets" / "operators.json").read_text()
)
_GROUPS = {
    "Command": {
        "CallExpr",
        "IfClause",
        "WhileClause",
        "ForClause",
        "CaseClause",
        "Block",
        "Subshell",
        "BinaryCmd",
        "FuncDecl",
        "ArithmCmd",
        "TestClause",
        "DeclClause",
        "LetClause",
        "TimeClause",
        "CoprocClause",
        "TestDecl",
    },
    "WordPart": {
        "Lit",
        "SglQuoted",
        "DblQuoted",
        "ParamExp",
        "CmdSubst",
        "ArithmExp",
        "ProcSubst",
        "ExtGlob",
        "BraceExp",
    },
    "ArithmExpr": {"Word", "BinaryArithm", "UnaryArithm", "ParenArithm", "FlagsArithm"},
    "TestExpr": {"Word", "BinaryTest", "UnaryTest", "ParenTest"},
    "Loop": {"WordIter", "CStyleLoop"},
}
_CONTAINERS = {"Slice", "Replace", "Expansion"}
_REQUIRED = {
    "FuncDecl": {"Name", "Body"},
    "BinaryCmd": {"Op", "X", "Y"},
    "BinaryTest": {"Op", "X", "Y"},
    "BinaryArithm": {"Op", "X", "Y"},
    "ForClause": {"Loop"},
    "WhileClause": {"Cond", "Do"},
    "CaseClause": {"Word"},
    "CaseItem": {"Patterns"},
    "UnaryTest": {"Op", "X"},
    "UnaryArithm": {"Op", "X"},
    "TestClause": {"X"},
    "Word": {"Parts"},
    "Stmt": {"Position"},
}


class Validator:
    """Hold only the source location index and resource counters during decoding."""

    def __init__(self, source: str):
        data = source.encode("utf-8")
        self.source = data
        self.size = len(data)
        self.starts = [0, *(i + 1 for i, byte in enumerate(data) if byte == 10)]
        self.nodes = 0

    def position(self, value: object) -> None:
        """Verify byte offset, line and byte column agree with the input."""
        if not isinstance(value, dict) or set(value) != {"Offset", "Line", "Col"}:
            raise ValueError("invalid position shape")
        if any(type(item) is not int for item in value.values()):
            raise ValueError("invalid position numbers")
        offset = value["Offset"]
        if not 0 <= offset <= self.size:
            raise ValueError("position outside source")
        line = bisect_right(self.starts, offset)
        # End positions at a newline belong to the preceding line, as in Go Pos.
        if (value["Line"], value["Col"]) != (line, offset - self.starts[line - 1] + 1):
            raise ValueError("position disagrees with source")

    def value(self, value: object, expected: str, depth: int) -> None:
        """Validate one descriptor, delegating lists, positions and AST nodes."""
        if depth > MAX_DEPTH:
            raise ValueError("AST depth limit exceeded")
        if expected.startswith("[]"):
            self.sequence(value, expected[2:], depth)
        elif expected == "Pos":
            self.position(value)
        elif expected.lstrip("*") in _SCHEMA or expected in _GROUPS:
            self.node(value, expected.lstrip("*"), depth)
        else:
            self.scalar(value, expected)

    def sequence(self, value: object, expected: str, depth: int) -> None:
        """Validate a present nonempty sequence; omitted slices encode empty."""
        if not isinstance(value, list) or not value or len(value) > MAX_NODES:
            raise ValueError("invalid or oversized AST sequence")
        for item in value:
            self.value(item, expected, depth + 1)

    def scalar(self, value: object, expected: str) -> None:
        """Reject wrong primitive types including bool masquerading as int."""
        types = {"string": str, "bool": bool, "OptState": int}
        if type(value) is not types.get(expected, str):
            raise ValueError("invalid AST scalar")
        if expected in _OPERATORS and value not in _OPERATORS[expected]:
            raise ValueError("unknown AST operator")
        if expected == "OptState" and value not in {0, 1, 2}:
            raise ValueError("unknown AST option state")

    def kind(self, value: dict, expected: str) -> str:
        """Resolve only schema-known types, never accept an unknown fallback."""
        kind = value.get("Type", expected)
        allowed = _GROUPS.get(expected, {expected})
        if not isinstance(kind, str) or kind not in allowed:
            raise ValueError("unknown or unexpected AST node type")
        return kind

    def node(self, value: object, expected: str, depth: int) -> None:
        """Check a concrete node's fields and annotate its internal kind."""
        if not isinstance(value, dict):
            raise TypeError("invalid AST node")
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise ValueError("AST node limit exceeded")
        kind = self.kind(value, expected)
        fields = _SCHEMA[kind]
        required = set(_REQUIRED.get(kind, ()))
        if kind not in _CONTAINERS and value != {"Type": "File"}:
            required.update(("Pos", "End"))
        if not required.issubset(value) or set(value) - fields.keys() - {
            "Type",
            "Pos",
            "End",
        }:
            raise ValueError("missing or unknown AST fields")
        self.fields(value, fields, depth)
        self.required_shape(value, kind)
        value["_kind"] = kind

    def required_shape(self, node: dict, kind: str) -> None:
        """Reject absent semantic fields that could turn decisions into clean zeros."""
        checks = {
            "IfClause": self.condition,
            "CallExpr": self.call,
            "FuncDecl": self.function,
            "File": self.file,
        }
        if check := checks.get(kind):
            check(node)

    def call(self, node: dict) -> None:
        """A simple command must contain arguments or assignments."""
        if not (node.get("Args") or node.get("Assigns")):
            raise ValueError("empty call node")

    def function(self, node: dict) -> None:
        """Supported dialects provide a nonempty name for every function."""
        if not node["Name"].get("Value"):
            raise ValueError("missing function name")

    def file(self, node: dict) -> None:
        """Only empty source can legitimately omit every root observation."""
        if not (node.get("Stmts") or node.get("Last")) and self.source.strip():
            raise ValueError("missing file observations")

    def condition(self, node: dict) -> None:
        """Only an else wrapper may omit an if/elif condition."""
        if not node.get("Cond"):
            start = node["Pos"]["Offset"]
            if not self.source[start:].startswith(b"else"):
                raise ValueError("conditional missing condition")

    def fields(self, value: dict, fields: dict, depth: int) -> None:
        """Check every present field using the pinned descriptor table."""
        for key, item in value.items():
            if key != "Type":
                self.value(
                    item, "Pos" if key in {"Pos", "End"} else fields[key], depth + 1
                )
        if "Pos" in value and value["Pos"]["Offset"] > value["End"]["Offset"]:
            raise ValueError("reversed AST span")


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject duplicate fields before JSON could silently overwrite evidence."""
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate AST field")
    return result


def decode(output: str, source: str) -> dict:
    """Reject empty, oversized or structurally invalid AST output."""
    if not output or len(output.encode("utf-8")) > MAX_JSON_BYTES:
        raise ValueError("empty or oversized AST output")
    tree = json.loads(output, object_pairs_hook=unique_object)
    if not isinstance(tree, dict) or tree.get("Type") != "File":
        raise ValueError("missing typed file root")
    Validator(source).value(tree, "File", 0)
    return tree
