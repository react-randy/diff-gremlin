"""Inventory coverage must not become clean after skipped source paths."""

from pathlib import Path

from diff_gremlin import inventory


def test_observed_languages_and_all_regular_files(tmp_path):
    for name in (
        "main.py",
        "ui.tsx",
        "script.js",
        "App.java",
        "lib.rs",
        "main.go",
        "core.c",
        "core.cpp",
        "app.rb",
        "app.swift",
        "app.m",
        "app.scala",
        "app.lua",
        "settings.json",
    ):
        (tmp_path / name).write_text("source")
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").write_text("test")
    result = inventory.collect_inventory(tmp_path)
    assert set(result.languages) == {
        "python",
        "typescript",
        "javascript",
        "java",
        "rust",
        "go",
        "c",
        "cpp",
        "ruby",
        "swift",
        "objc",
        "scala",
        "lua",
    }
    assert len(result.files) == 16
    assert len(result.production_files) == 13
    assert result.stage.status == "ok"


def test_markers_do_not_fabricate_language_coverage(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "pyproject.toml").write_text("")
    assert inventory.collect_inventory(tmp_path).languages == ()


def test_vendors_excluded_with_reasons_and_symlinks_visible(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "secret.py").write_text("ignored")
    (tmp_path / "main.py").write_text("regular")
    (tmp_path / "linked.py").symlink_to(tmp_path / "main.py")
    result = inventory.collect_inventory(tmp_path)
    assert [f.relative_path for f in result.files] == ["main.py"]
    assert result.stage.status == "limited"
    assert result.stage.metrics["excluded_directories"] == {"vendor": 1}
    assert "vendored" in result.stage.metrics["exclusion_reasons"]["vendor"]


def test_caps_and_read_failures_are_visible(tmp_path, monkeypatch):
    (tmp_path / "big.py").write_text("x" * 20)
    monkeypatch.setattr(inventory, "MAX_FILE_BYTES", 10)
    result = inventory.collect_inventory(tmp_path)
    assert result.stage.status == "limited"
    assert result.files == ()
    monkeypatch.setattr(inventory, "MAX_FILE_BYTES", 100)
    original = Path.open

    def unreadable(self, *args, **kwargs):
        raise PermissionError("controlled")

    # The scanner uses builtins.open, so intercept that exact boundary.
    import builtins

    monkeypatch.setattr(builtins, "open", unreadable)
    result = inventory.collect_inventory(tmp_path)
    assert result.stage.status == "limited"
    assert "unreadable" in result.stage.findings[0].message
    assert original


def test_test_name_detection_does_not_hide_contest_production_code():
    assert not inventory.is_test_path(Path("Contest.java"))
    assert inventory.is_test_path(Path("FeatureTest.java"))
    assert inventory.is_test_path(Path("widget.test.ts"))
