"""Ordinary source volume and native coordinate corruption are different cases."""

import pytest

from diff_gremlin.analyzers.javascript.coordinates import SourceCoordinates
from diff_gremlin.analyzers.javascript.lint import analyze_js_lint
from diff_gremlin.analyzers.javascript.types import analyze_ts_types
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.process import run


@pytest.mark.parametrize(
    "analyzer,suffix,language,tail",
    [
        (analyze_js_lint, ".js", "javascript", "console.log(missingName);"),
        (analyze_ts_types, ".ts", "typescript", "export const value: number = 'bad';"),
    ],
)
def test_native_diagnostics_survive_multi_file_source_above_former_budget(
    tmp_path, analyzer, suffix, language, tail
):
    root, scratch = tmp_path / "source", tmp_path / "scratch"
    root.mkdir()
    scratch.mkdir()
    files = []
    for name in ("First", "Second"):
        path = root / (name + suffix)
        path.write_text(
            "/*" + "a" * (2 * 1024 * 1024) + "*/\n" + tail, encoding="utf-8"
        )
        files.append(SourceFile(path, path.name, language, False, path.stat().st_size))
    context = ScanContext(
        root, tuple(files), tuple(files), (language,), "quick", 30, scratch, run
    )
    result = analyzer(context)
    assert result.status == "ok", result.reason
    assert result.analyzed_files == result.eligible_files == 2
    assert {finding.path for finding in result.findings} == {f.path.name for f in files}
    assert all(finding.line == 2 for finding in result.findings)


@pytest.mark.parametrize("contents", [b"x", b"xxxx"])
def test_source_size_change_cannot_validate_a_native_observation(tmp_path, contents):
    path = tmp_path / "source.js"
    path.write_bytes(b"xx")
    file = SourceFile(path, path.name, "javascript", False, 2)
    coordinates = SourceCoordinates((file,))
    path.write_bytes(contents)
    with pytest.raises(ValueError, match="inventoried size"):
        coordinates.validate(str(path.resolve()), 1, 1, "eslint")


def test_coordinate_line_memory_is_bounded(tmp_path, monkeypatch):
    path = tmp_path / "source.js"
    path.write_text("x\nx\nx\n", encoding="utf-8")
    file = SourceFile(path, path.name, "javascript", False, path.stat().st_size)
    monkeypatch.setattr(
        "diff_gremlin.analyzers.javascript.coordinates._MAX_CACHED_LINES", 2
    )
    with pytest.raises(ValueError, match="coordinate line budget"):
        SourceCoordinates((file,)).validate(str(path.resolve()), 1, 1, "eslint")


def test_source_per_file_budget_is_distinct_from_cumulative_budget(
    tmp_path, monkeypatch
):
    path = tmp_path / "source.js"
    path.write_bytes(b"abcd")
    file = SourceFile(path, path.name, "javascript", False, 4)
    monkeypatch.setattr(
        "diff_gremlin.analyzers.javascript.coordinates.MAX_FILE_BYTES", 2
    )
    with pytest.raises(ValueError, match="per-file coordinate"):
        SourceCoordinates((file,)).validate(str(path.resolve()), 1, 1, "eslint")
