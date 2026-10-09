"""Native immutable-tree controls for selected comparisons and diff locations."""

import base64
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from diff_gremlin.acquisition import changes, objects, tree
from diff_gremlin.acquisition.snapshots import acquire_comparison, acquire_source
from diff_gremlin.domain.sources import ReviewTarget
from diff_gremlin.inventory import MAX_FILES, collect_inventory
from diff_gremlin.source_scope import classify_content


def git(repo: Path, *args: str, content: str | None = None) -> str:
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *args],
        cwd=repo,
        env={
            "PATH": os.defpath,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        },
        input=content,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def repository(root: Path) -> Path:
    root.mkdir()
    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture@example.test")
    return root


def commit(root: Path, message: str) -> str:
    git(root, "add", "--all")
    git(root, "commit", "-m", message)
    return git(root, "rev-parse", "HEAD")


def files(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
    }


@pytest.fixture
def comparison(tmp_path):
    root = repository(tmp_path / "repo")
    (root / "src").mkdir()
    (root / "src" / "edited.py").write_text("one\ntwo\nthree\nfour\nfive\n")
    (root / "src" / "gone.py").write_text("removed\n")
    (root / "old.py").write_text("renamed\n")
    (root / "unchanged.py").write_text("same\n")
    base = commit(root, "base")
    (root / "src" / "edited.py").write_text(
        "one\nreplacement\nthree\nfour\nfive\nadded\n"
    )
    (root / "src" / "gone.py").unlink()
    (root / "old.py").rename(root / "new.py")
    (root / "src" / "empty.py").touch()
    head = commit(root, "head")
    return root, base, head


def test_default_full_scope_and_correct_side_hunk_intervals(comparison):
    root, base, head = comparison
    with acquire_comparison(str(root), base, head) as pair:
        assert pair.base.selection is None and pair.head.selection is None
        assert files(pair.base.root) == {
            "src/edited.py",
            "src/gone.py",
            "old.py",
            "unchanged.py",
        }
        assert files(pair.head.root) == {
            "src/edited.py",
            "src/empty.py",
            "new.py",
            "unchanged.py",
        }
        assert pair.base_changed_lines == {
            "old.py": ((1, 1),),
            "src/edited.py": ((2, 2),),
            "src/gone.py": ((1, 1),),
        }
        assert pair.head_changed_lines == {
            "new.py": ((1, 1),),
            "src/edited.py": ((2, 2), (6, 6)),
            "src/empty.py": (),
        }
        assert git(pair.base.history_repo, "rev-parse", "HEAD") == base
        assert git(pair.head.history_repo, "rev-parse", "HEAD") == head


def test_changed_selection_and_literal_subtree_intersect(comparison):
    root, base, head = comparison
    with acquire_comparison(str(root), base, head, changed_paths=True) as pair:
        assert files(pair.base.root) == {"src/edited.py", "src/gone.py", "old.py"}
        assert files(pair.head.root) == {"src/edited.py", "src/empty.py", "new.py"}
        assert pair.base.selection["mode"] == "changed-paths"
        assert pair.head.selection["partial"] is True
        assert pair.head.selection["counts"] == {
            "total": 4,
            "selected": 3,
            "omitted": 1,
        }
    with acquire_comparison(
        str(root), base, head, paths=("src/",), changed_paths=True
    ) as pair:
        assert files(pair.base.root) == {"src/edited.py", "src/gone.py"}
        assert files(pair.head.root) == {"src/edited.py", "src/empty.py"}
        assert pair.base.selection["mode"] == "paths-and-changed-paths"
        assert pair.base.selection["paths"] == ["src"]
        assert "old.py" not in pair.base_changed_lines
    with acquire_comparison(str(root), base, head, paths=("src/edited.py",)) as pair:
        assert files(pair.base.root) == files(pair.head.root) == {"src/edited.py"}


def test_empty_changed_scope_and_nonmatching_literal_stay_empty(comparison):
    root, base, _head = comparison
    for options in ({"changed_paths": True}, {"paths": ("absent",)}):
        with acquire_comparison(str(root), base, base, **options) as pair:
            assert files(pair.base.root) == files(pair.head.root) == set()
            assert pair.base.selection["counts"] == {
                "total": 4,
                "selected": 0,
                "omitted": 4,
            }
            assert pair.base_changed_lines == pair.head_changed_lines == {}


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/source",
        "../outside",
        "src/../outside",
        ".git/config",
        ":(glob)*",
        "*.py",
        "src//code.py",
        "./src",
        "C:\\source",
        "src\x00file",
        "src\nfile",
    ],
)
def test_unsafe_or_pattern_selectors_are_rejected_before_source_access(tmp_path, path):
    with (
        pytest.raises(ValueError, match="Path selection"),
        acquire_comparison(str(tmp_path / "absent"), "HEAD", "HEAD", paths=(path,)),
    ):
        pass


def test_literal_prefix_does_not_select_sibling_name(comparison):
    root, base, head = comparison
    with acquire_comparison(str(root), base, head, paths=("sr",)) as pair:
        assert files(pair.base.root) == set()


def test_large_native_tree_selected_before_file_limit(tmp_path):
    root = repository(tmp_path / "large")
    original = git(root, "hash-object", "-w", "--stdin", content="value = 1\n")
    changed = git(root, "hash-object", "-w", "--stdin", content="value = 2\n")
    rows = [f"100644 blob {original}\tfile{index:05d}.py\n" for index in range(27001)]
    before_tree = git(root, "mktree", content="".join(rows))
    base = git(root, "commit-tree", before_tree, "-m", "large base")
    rows[0] = f"100644 blob {changed}\tfile00000.py\n"
    after_tree = git(root, "mktree", content="".join(rows))
    head = git(root, "commit-tree", after_tree, "-p", base, "-m", "large head")
    git(root, "update-ref", "refs/heads/main", head)
    with (
        pytest.raises(RuntimeError, match=f"limit {MAX_FILES}; found 27001 files"),
        acquire_comparison(str(root), base, head),
    ):
        pass
    for options in ({"paths": ("file00000.py",)}, {"changed_paths": True}):
        with acquire_comparison(str(root), base, head, **options) as pair:
            assert files(pair.base.root) == files(pair.head.root) == {"file00000.py"}
            assert (pair.head.root / "file00000.py").read_text() == "value = 2\n"
            assert pair.head.selection["counts"] == {
                "total": 27001,
                "selected": 1,
                "omitted": 27000,
            }
            assert pair.head_changed_lines == {"file00000.py": ((1, 1),)}


def test_unselected_escaping_symlink_still_fails(comparison):
    root, base, _head = comparison
    (root / "escape.py").symlink_to("../outside.py")
    head = commit(root, "unsafe link")
    with (
        pytest.raises(RuntimeError, match="escapes"),
        acquire_comparison(str(root), base, head, paths=("src",)),
    ):
        pass


def test_selected_links_are_inert_and_safe_unselected_links_not_materialized(
    comparison,
):
    root, base, _head = comparison
    (root / "link.py").symlink_to("src/edited.py")
    head = commit(root, "safe link")
    with acquire_comparison(str(root), base, head, paths=("link.py",)) as pair:
        assert (pair.head.root / "link.py").is_symlink()
        assert not (pair.head.root / "link.py").exists()
        assert collect_inventory(pair.head.root).stage.status == "limited"
    with acquire_comparison(str(root), base, head, paths=("src",)) as pair:
        assert not (pair.head.root / "link.py").is_symlink()


def test_selected_file_byte_and_metadata_limits_remain(comparison, monkeypatch):
    root, base, head = comparison
    monkeypatch.setattr(objects, "MAX_FILE_BYTES", 4)
    with acquire_comparison(str(root), base, head, paths=("src/edited.py",)) as pair:
        assert not (pair.head.root / "src" / "edited.py").exists()
        assert pair.head.scope_manifest[0].classification == "possible-source"
    monkeypatch.setattr(tree, "MAX_ENTRIES", 2)
    with (
        pytest.raises(RuntimeError, match="metadata exceeds limit 2; found at least 3"),
        acquire_comparison(str(root), base, head, paths=("src/edited.py",)),
    ):
        pass


def test_aggregate_budget_keeps_possible_source_omission(comparison, monkeypatch):
    root, base, head = comparison
    monkeypatch.setattr(objects, "MAX_TREE_BYTES", 4)
    with acquire_comparison(str(root), base, head, paths=("src",)) as pair:
        assert any(
            row.classification == "possible-source" for row in pair.head.scope_manifest
        )


def test_diff_output_budget_yields_unknown_lines_not_false_clean(
    comparison, monkeypatch
):
    root, base, head = comparison
    monkeypatch.setattr(changes, "MAX_METADATA_BYTES", 16)
    with acquire_comparison(str(root), base, head, paths=("src",)) as pair:
        assert pair.base_changed_lines is None and pair.head_changed_lines is None
    with (
        pytest.raises(RuntimeError, match="Git diff failed"),
        acquire_comparison(str(root), base, head, changed_paths=True),
    ):
        pass


def test_fork_review_uses_captured_pins_and_both_object_stores(comparison, tmp_path):
    root, base, _head = comparison
    fork = tmp_path / "fork"
    shutil.copytree(root, fork)
    (fork / "fork.py").write_text("captured\n")
    captured = commit(fork, "fork captured")
    review = ReviewTarget(
        "github",
        "https://github.com/team/repo/pull/1",
        "team/repo",
        1,
        str(root),
        str(fork),
        base,
        captured,
    )
    (fork / "fork.py").write_text("moved\n")
    commit(fork, "moving head")
    with acquire_comparison(
        str(root), "main", "main", review=review, changed_paths=True
    ) as pair:
        assert pair.base.identity.commit_sha == base
        assert pair.head.identity.commit_sha == captured
        assert (pair.head.root / "fork.py").read_text() == "captured\n"
        assert pair.head_changed_lines["fork.py"] == ((1, 1),)
        assert "fork.py" not in pair.base_changed_lines


def test_selected_comparison_preserves_branch_index_dirty_state_and_config(
    comparison, tmp_path, monkeypatch
):
    root, base, head = comparison
    (root / "unchanged.py").write_text("staged\n")
    git(root, "add", "unchanged.py")
    (root / "unchanged.py").write_text("unstaged\n")
    (root / "untracked.py").write_text("untracked\n")
    config = tmp_path / "global-config"
    config.write_text("[safe]\n\tdirectory = /unchanged\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    before = {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    status = git(root, "status", "--porcelain=v1")
    branch = git(root, "symbolic-ref", "HEAD")
    with acquire_comparison(str(root), base, head, changed_paths=True) as pair:
        workspace = pair.base.root.parent
        assert not pair.base.identity.dirty and not pair.head.identity.dirty
    assert not workspace.exists()
    assert before == {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    assert git(root, "status", "--porcelain=v1") == status
    assert git(root, "symbolic-ref", "HEAD") == branch
    assert config.read_text() == "[safe]\n\tdirectory = /unchanged\n"
    with acquire_source(str(root)) as snapshot:
        assert snapshot.selection is None and snapshot.identity.dirty
        assert (snapshot.root / "untracked.py").exists()


def test_newline_filename_is_taken_from_nul_metadata(tmp_path):
    root = repository(tmp_path / "newline")
    name = "odd\nname.py"
    (root / name).write_text("old\n")
    base = commit(root, "base")
    (root / name).write_text("new\n")
    head = commit(root, "head")
    with acquire_comparison(str(root), base, head, changed_paths=True) as pair:
        assert pair.base_changed_lines == pair.head_changed_lines == {name: ((1, 1),)}


def test_source_controls_cannot_inject_diff_hunk_metadata(tmp_path):
    root = repository(tmp_path / "controls")
    (root / "code.py").write_text("original\n")
    base = commit(root, "base")
    (root / "code.py").write_text("changed\v@@ -999 +888 @@\f diff --git injected\n")
    head = commit(root, "head")
    with acquire_comparison(str(root), base, head) as pair:
        assert (
            pair.base_changed_lines == pair.head_changed_lines == {"code.py": ((1, 1),)}
        )


def test_selected_snapshot_cleanup_on_consumer_failure(comparison):
    root, base, head = comparison
    with (
        pytest.raises(RuntimeError, match="consumer"),
        acquire_comparison(str(root), base, head, paths=("src",)) as pair,
    ):
        workspace = pair.base.root.parent
        raise RuntimeError("consumer failed")
    assert not workspace.exists()


def icon() -> bytes:
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jR5kAAAAASUVORK5CYII="
    )
    return (
        b"\x00\x00\x01\x00\x01\x00"
        + struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, len(png), 22)
        + png
    )


def test_valid_ico_classified_from_bytes_and_source_filename_retains_gap():
    assert classify_content("favicon.ico", icon())[0] == "binary-asset"
    assert classify_content("arbitrary.dat", icon())[0] == "binary-asset"
    assert classify_content("source.py", icon())[0] == "possible-source"
    assert classify_content("favicon.ico", b"print('actual source')\n")[0] == "text"
    for content in (
        icon()[:6],
        icon()[:-1],
        icon() + b"source = True\n",
        b"\x00\x00\x01\x00\x01\x00malicious source",
    ):
        assert classify_content("favicon.ico", content)[0] == "possible-source"


def test_ico_bitmap_and_adversarial_directory_validation():
    bitmap = (
        struct.pack("<IiiHHIIiiII", 40, 1, 2, 1, 32, 0, 4, 0, 0, 0, 0)
        + b"\x00\x00\x00\xff"
        + b"\x00" * 4
    )
    content = (
        b"\x00\x00\x01\x00\x01\x00"
        + struct.pack("<BBBBHHII", 1, 1, 0, 0, 1, 32, len(bitmap), 22)
        + bitmap
    )
    assert classify_content("favicon.ico", content)[0] == "binary-asset"
    for altered in (
        content[:4] + b"\xff\xff" + content[6:],
        content[:18] + b"\xff" * 4 + content[22:],
        content[:-1],
    ):
        assert classify_content("favicon.ico", altered)[0] == "possible-source"


def test_ico_asset_does_not_limit_native_ref_inventory(tmp_path):
    root = repository(tmp_path / "icons")
    (root / "favicon.ico").write_bytes(icon())
    (root / "main.py").write_text("answer = 1\n")
    head = commit(root, "icon")
    with acquire_source(str(root), ref=head) as snapshot:
        inventory = collect_inventory(snapshot.root, snapshot.scope_manifest)
        assert inventory.stage.status == "ok"
        assert inventory.stage.metrics["binary_asset_files"] == 1
        assert inventory.stage.metrics["omitted_possible_source_files"] == 0
