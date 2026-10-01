"""Repository facts distinguish test files from empty test directories."""

from diff_gremlin.analyzers.hygiene import analyze_hygiene
from diff_gremlin.domain.context import ScanContext, SourceFile


def context(tmp_path, source):
    files = []
    for name, text, is_test in source:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        files.append(SourceFile(path, name, "text", is_test, path.stat().st_size))
    return ScanContext(
        tmp_path,
        tuple(files),
        (),
        (),
        "full",
        1,
        tmp_path,
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("Hygiene must not execute source")),
    )


def test_empty_test_directory_does_not_count_as_suite(tmp_path):
    (tmp_path / "tests").mkdir()
    result = analyze_hygiene(context(tmp_path, [("tests/test_empty.py", "", True)]))
    assert result.status == "ok"
    assert result.metrics["checks"]["test_files"] is False


def test_named_hygiene_facts_are_transparent(tmp_path):
    source = [
        ("LICENSE", "MIT fixture", False),
        ("README.md", "A readable project description. " * 5, False),
        ("tests/test_example.py", "def test_something(): assert True", True),
        (".gitignore", "*.pyc", False),
        (".github/workflows/check.yml", "name: checks", False),
        ("uv.lock", "# lock fixture", False),
    ]
    result = analyze_hygiene(context(tmp_path, source))
    assert all(result.metrics["checks"].values())
    assert result.metrics["present_count"] == result.metrics["check_count"] == 6
    assert not result.findings
    assert "unverified" in result.reason


def test_unreadable_readme_limits_evidence(tmp_path):
    ctx = context(tmp_path, [("README.md", "description " * 20, False)])
    ctx.files[0].path.unlink()
    result = analyze_hygiene(ctx)
    assert result.status == "limited" and result.analyzed_files == 0
    assert any(f.rule == "hygiene.unreadable" for f in result.findings)
