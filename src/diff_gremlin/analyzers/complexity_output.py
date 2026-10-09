"""Validate Lizard XML observations against the exact production inventory."""

import ast
import xml.etree.ElementTree as ET
from collections import Counter

from diff_gremlin.analyzers.locations import SourceLocations
from diff_gremlin.analyzers.python.declarations import functions as python_functions
from diff_gremlin.analyzers.python.declarations import missing_declarations
from diff_gremlin.domain.context import ScanContext, SourceFile


def _file_counts(
    locations: SourceLocations, files: tuple[SourceFile, ...], measure: ET.Element
) -> dict[str, int]:
    seen = {}
    for item in measure.findall("item"):
        path = locations.relative(item.attrib.get("name"))
        if path in seen:
            raise ValueError("duplicate Lizard file observation")
        seen[path] = _values(item, 4, signed_ncss=True)[3]
    if set(seen) != {file.relative_path for file in files}:
        raise ValueError("Lizard did not cover the eligible file inventory")
    return seen


def _verify_function_counts(seen: dict[str, int], functions: list[dict]) -> None:
    counts = Counter(row["file"] for row in functions)
    for path, expected in seen.items():
        if counts[path] != expected:
            raise ValueError("Lizard file count disagrees with function observations")


def _functions_by_file(functions: list[dict]) -> dict[str, list[dict]]:
    grouped = {}
    for row in functions:
        grouped.setdefault(row["file"], []).append(row)
    return grouped


def _python_declarations(
    files: tuple[SourceFile, ...], functions: list[dict]
) -> list[dict]:
    grouped = _functions_by_file(functions)
    return [
        declaration
        for file in files
        if file.path.suffix.lower() == ".py"
        for declaration in missing_declarations(
            file, grouped.get(file.relative_path, [])
        )
    ]


def _qualified_python_names(
    files: tuple[SourceFile, ...], functions: list[dict]
) -> None:
    """Supply lexical class owners omitted by Lizard's Python XML names."""
    grouped = _functions_by_file(functions)
    for file in files:
        if file.path.suffix.lower() != ".py":
            continue
        tree = ast.parse(file.path.read_text(encoding="utf-8"))
        names = {
            node.lineno: (node.name, name) for node, name in python_functions(tree)
        }
        for row in grouped.get(file.relative_path, []):
            declaration = names.get(row["line"])
            if declaration and row["function"].split(".")[-1] == declaration[0]:
                row["function"] = declaration[1]


def _values(item: ET.Element, length: int, *, signed_ncss: bool = False) -> list[int]:
    values = [int(value.text or "") for value in item.findall("value")]
    if len(values) != length or any(
        value < 0
        for index, value in enumerate(values)
        if not (signed_ncss and index == 1)
    ):
        raise ValueError("invalid Lizard metric row")
    return values


def _functions(locations: SourceLocations, measure: ET.Element) -> list[dict]:
    observations = {}
    for item in measure.findall("item"):
        name, location = item.attrib["name"].rsplit(" at ", 1)
        path, line_text = location.rsplit(":", 1)
        path = locations.relative(path)
        line = int(line_text)
        # Lizard 1.24 subtracts multiline string NCSS twice in some valid Python
        # bodies. NCSS is unused telemetry; CCN and identity remain strict.
        cc = _values(item, 3, signed_ncss=True)[2]
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


def observations(
    ctx: ScanContext, files: tuple[SourceFile, ...], text: str
) -> list[dict]:
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
    locations = SourceLocations(ctx.root, files)
    seen = _file_counts(locations, files, file_measure)
    functions = _functions(locations, function_measure)
    _verify_function_counts(seen, functions)
    functions += _python_declarations(files, functions)
    _qualified_python_names(files, functions)
    return functions
