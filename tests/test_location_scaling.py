"""Batch controls for canonical source membership and linear resolution work."""

import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from test_python_analyzers import FakeRunner, make_context

from diff_gremlin.analyzers.complexity_output import (
    _python_declarations,
    _verify_function_counts,
    observations,
)
from diff_gremlin.analyzers.locations import relative_location
from diff_gremlin.analyzers.python.maintainability import _indices
from diff_gremlin.analyzers.python.pyscn_clones import _group_findings
from diff_gremlin.analyzers.python.pyscn_coverage import coverage
from diff_gremlin.analyzers.python.pyscn_deadcode import _located_findings
from diff_gremlin.analyzers.python.ruff import _findings
from diff_gremlin.analyzers.python.types import _diagnostics


def lizard_report(files):
    functions = "".join(
        f'<item name="f{line}(...) at {file.relative_path}:{line}">'
        "<value>1</value><value>1</value><value>1</value></item>"
        for file in files
        for line in (1, 2, 3)
    )
    counts = "".join(
        f'<item name="{file.relative_path}"><value>1</value>'
        "<value>1</value><value>1</value><value>3</value></item>"
        for file in files
    )
    return (
        f'<cppncss><measure type="Function">{functions}</measure>'
        f'<measure type="File">{counts}</measure></cppncss>'
    )


def located_row(path, line):
    return {"file_path": path, "start_line": line, "end_line": line}


def batch_data(kind, files):
    paths = [file.relative_path for file in files]
    if kind == "lizard":
        return lizard_report(files), 4 * len(files)
    if kind == "coverage":
        return {
            "schema_version": 1,
            "summary": {
                "total_files": len(files),
                "analyzed_files": len(files),
                "skipped_files": 0,
            },
            "complexity": {"raw_metrics": [{"file_path": path} for path in paths]},
        }, len(files)
    if kind == "indices":
        return json.dumps(
            {"version": "6.0.1", "files": {path: {"mi": 50} for path in paths}}
        ), len(files)
    if kind == "deadcode":
        return {
            "files": [
                {
                    "file_path": path,
                    "functions": [
                        {
                            "name": "choose",
                            "findings": [
                                {
                                    "location": located_row(path, line),
                                    "reason": "unreachable",
                                    "severity": "warning",
                                }
                                for line in (1, 2, 3)
                            ],
                        }
                    ],
                }
                for path in paths
            ]
        }, 4 * len(files)
    if kind == "clones":
        return [
            {
                "id": 1,
                "clones": [
                    {"location": located_row(path, line)}
                    for path in paths
                    for line in (1, 2, 3)
                ],
            }
        ], 3 * len(files)
    if kind == "ruff":
        return json.dumps(
            [
                {
                    "filename": path,
                    "location": {"row": line, "column": 1},
                    "code": "F821",
                    "message": "undefined",
                }
                for path in paths
                for line in (1, 2, 3)
            ]
        ), 3 * len(files)
    return json.dumps(
        {
            "errors": [
                {
                    "path": path,
                    "line": line,
                    "column": 1,
                    "name": "bad-return",
                    "severity": "error",
                }
                for path in paths
                for line in (1, 2, 3)
            ]
        }
    ), 3 * len(files)


BATCHES = {
    "lizard": observations,
    "coverage": coverage,
    "indices": _indices,
    "deadcode": _located_findings,
    "clones": _group_findings,
    "ruff": _findings,
    "types": _diagnostics,
}


@pytest.mark.parametrize("kind", BATCHES)
@pytest.mark.parametrize("size", [16, 256])
def test_batch_resolves_inventory_once(tmp_path, kind, size):
    ctx = make_context(
        tmp_path,
        FakeRunner(""),
        {
            f"Example{index}.java": "// first\n// second\n// third\n"
            for index in range(size)
        },
    )
    data, locations = batch_data(kind, ctx.files)
    original = Path.resolve
    calls = []

    def counted(path, *args, **kwargs):
        calls.append(path)
        return original(path, *args, **kwargs)

    with patch.object(Path, "resolve", counted):
        BATCHES[kind](ctx, ctx.files, data)
    assert len(calls) == size + locations


@pytest.mark.parametrize("kind", ["lizard", "ruff"])
def test_field_size_batch_resolves_inventory_once(tmp_path, kind):
    size = 1629
    ctx = make_context(
        tmp_path, FakeRunner(""), {f"Example{index}.java": "" for index in range(size)}
    )
    data, locations = batch_data(kind, ctx.files)
    # Canonical outcomes are computed natively before instrumentation. Reusing
    # them keeps the quadratic baseline control bounded without timing gates.
    canonical = {file.path: file.path.resolve() for file in ctx.files}
    calls = 0

    def counted(path, *args, **kwargs):
        nonlocal calls
        calls += 1
        return canonical[path]

    with patch.object(Path, "resolve", counted):
        BATCHES[kind](ctx, ctx.files, data)
    assert calls == size + locations


class CountedFunctions(list):
    def __init__(self, rows):
        super().__init__(rows)
        self.visits = 0

    def __iter__(self):
        for row in super().__iter__():
            self.visits += 1
            yield row


def test_lizard_function_counts_visit_each_row_once():
    rows = CountedFunctions(
        [{"file": path} for path in ("a.java", "b.java") for _ in range(3)]
    )
    _verify_function_counts({"a.java": 3, "b.java": 3, "empty.java": 0}, rows)
    assert rows.visits == len(rows)
    with pytest.raises(ValueError, match="count disagrees"):
        _verify_function_counts({"a.java": 2, "b.java": 3}, rows)


@pytest.mark.parametrize("value", [None, 1, "", "a\x00.py", "../outside.py"])
def test_invalid_membership_has_safe_cause(tmp_path, value):
    ctx = make_context(tmp_path, FakeRunner(""))
    with pytest.raises(ValueError) as raised:
        relative_location(ctx.root, value, ctx.files)
    assert str(tmp_path) not in str(raised.value)


def test_canonical_membership_and_batch_lifetime(tmp_path):
    from diff_gremlin.analyzers.locations import SourceLocations

    ctx = make_context(tmp_path, FakeRunner(""), {"folder with spaces/café.py": ""})
    file = ctx.files[0]
    locations = SourceLocations(ctx.root, ctx.files)
    alias = ctx.root / "alias.py"
    alias.symlink_to(file.path)
    assert locations.relative(file.relative_path) == file.relative_path
    assert locations.relative(str(file.path)) == file.relative_path
    assert locations.relative("alias.py") == file.relative_path
    outside = tmp_path / "outside.py"
    outside.write_text("")
    alias.unlink()
    alias.symlink_to(outside)
    with pytest.raises(ValueError, match="outside analyzed inventory"):
        locations.relative("alias.py")
    with pytest.raises(ValueError):
        locations.relative(str(outside))

    other_path = ctx.root / "other.py"
    other_path.write_text("")
    other_file = replace(file, path=other_path, relative_path="other.py")
    other_ctx = replace(ctx, files=(other_file,), production_files=(other_file,))
    other = SourceLocations(other_ctx.root, other_ctx.files)
    assert other.relative("other.py") == "other.py"
    with pytest.raises(ValueError):
        locations.relative("other.py")
    with pytest.raises(ValueError):
        other.relative(file.relative_path)

    second_root = tmp_path / "second"
    second_root.mkdir()
    second_path = second_root / "other.py"
    second_path.write_text("")
    second_file = replace(other_file, path=second_path)
    second = SourceLocations(second_root, (second_file,))
    assert second.relative("other.py") == "other.py"
    with pytest.raises(ValueError):
        second.relative(str(other_path))


def test_python_declarations_visit_each_observation_once(tmp_path):
    ctx = make_context(
        tmp_path,
        FakeRunner(""),
        {f"example{index}.py": "def choose():\n    return 1\n" for index in range(16)},
    )
    rows = CountedFunctions(
        [{"file": file.relative_path, "line": 1} for file in ctx.files]
    )
    assert _python_declarations(ctx.files, rows) == []
    assert rows.visits == len(rows)
