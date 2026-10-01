"""Validate Lizard XML observations against the exact production inventory."""

import ast
import xml.etree.ElementTree as ET

from diff_gremlin.analyzers.locations import relative_location
from diff_gremlin.domain.context import ScanContext, SourceFile


def _file_counts(
    ctx: ScanContext, files: tuple[SourceFile, ...], measure: ET.Element
) -> dict[str, int]:
    seen = {}
    for item in measure.findall("item"):
        path = relative_location(ctx.root, item.attrib.get("name"), files)
        if path in seen:
            raise ValueError("duplicate Lizard file observation")
        seen[path] = _values(item, 4)[3]
    if set(seen) != {file.relative_path for file in files}:
        raise ValueError("Lizard did not cover the eligible file inventory")
    return seen


def _verify_function_counts(seen: dict[str, int], functions: list[dict]) -> None:
    for path, expected in seen.items():
        if sum(row["file"] == path for row in functions) != expected:
            raise ValueError("Lizard file count disagrees with function observations")


def _verify_python_declarations(files: tuple[SourceFile, ...], seen: dict[str, int]) -> None:
    for file in files:
        if file.path.suffix.lower() == ".py":
            tree = ast.parse(file.path.read_text(encoding="utf-8"))
            expected = sum(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree)
            )
            if expected != seen[file.relative_path]:
                raise ValueError("Lizard missed Python function declarations")


def _values(item: ET.Element, length: int) -> list[int]:
    values = [int(value.text or "") for value in item.findall("value")]
    if len(values) != length or any(value < 0 for value in values):
        raise ValueError("invalid Lizard metric row")
    return values


def _functions(ctx: ScanContext, files: tuple[SourceFile, ...], measure: ET.Element) -> list[dict]:
    observations = {}
    for item in measure.findall("item"):
        name, location = item.attrib["name"].rsplit(" at ", 1)
        path, line_text = location.rsplit(":", 1)
        path = relative_location(ctx.root, path, files)
        line = int(line_text)
        cc = _values(item, 3)[2]
        if line < 1 or cc < 1 or not name.endswith("(...)"):
            raise ValueError("invalid Lizard function location")
        name = name[:-5]
        identity = (path, line, name)
        if identity in observations:
            raise ValueError("duplicate Lizard function observation")
        observations[identity] = {
            "file": path,
            "function": name,
            "line": line,
            "cc": cc,
        }
    return sorted(
        observations.values(),
        key=lambda row: (row["file"], row["line"], row["function"]),
    )


def observations(ctx: ScanContext, files: tuple[SourceFile, ...], text: str) -> list[dict]:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("unsupported XML declaration")
    root = ET.fromstring(text)
    measures = root.findall("measure")
    if root.tag != "cppncss" or len(measures) != 2:
        raise ValueError("invalid Lizard root")
    function_measure = root.find("measure[@type='Function']")
    file_measure = root.find("measure[@type='File']")
    if function_measure is None or file_measure is None:
        raise ValueError("missing Lizard file or function measure")
    seen = _file_counts(ctx, files, file_measure)
    functions = _functions(ctx, files, function_measure)
    _verify_function_counts(seen, functions)
    _verify_python_declarations(files, seen)
    return functions
