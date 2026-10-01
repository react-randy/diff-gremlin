"""Exercise review findings through bounded acquisition and public CLI journeys."""

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "src"
CLI_BOOTSTRAP = (
    "import sys; sys.path.insert(0, sys.argv.pop(1)); "
    "from diff_gremlin.cli.main import main; raise SystemExit(main())"
)


@pytest.fixture
def child_environment(tmp_path):
    home = tmp_path / "home"
    workspace = tmp_path / "disposable scans"
    home.mkdir()
    workspace.mkdir()
    return {
        "PATH": os.defpath,
        "HOME": str(home),
        "TMPDIR": str(workspace),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C.UTF-8",
    }


def git(repo, environment, *arguments):
    result = subprocess.run(
        ["git", "-c", "core.hooksPath=/dev/null", *arguments],
        cwd=repo,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    )
    return result.stdout.strip()


@pytest.fixture
def repository(tmp_path, child_environment):
    repo = tmp_path / "caller repo"
    repo.mkdir()
    git(repo, child_environment, "init", "-b", "main")
    git(repo, child_environment, "config", "user.name", "Fixture")
    git(repo, child_environment, "config", "user.email", "fixture@example.test")
    (repo / "notes.txt").write_text("committed text\n")
    (repo / "LICENSE").write_text("MIT License\n")
    git(repo, child_environment, "add", ".")
    git(repo, child_environment, "commit", "-m", "base")
    return repo


def fingerprint(repo):
    return {
        path.relative_to(repo).as_posix(): path.read_bytes()
        for path in repo.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def cli(repo, environment, *arguments):
    before = fingerprint(repo)
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", CLI_BOOTSTRAP, str(SOURCE), *arguments],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert fingerprint(repo) == before, "CLI changed caller source or Git metadata"
    assert not list(Path(environment["TMPDIR"]).iterdir()), "scan resources survived CLI exit"
    assert result.returncode in {0, 1, 3}, result.stderr
    assert not result.stderr, result.stderr
    return result


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO support")
def test_regular_source_replaced_by_fifo_fails_without_blocking(tmp_path, child_environment):
    source = tmp_path / "source"
    source.mkdir()
    (source / "race.txt").write_bytes(b"original source\n")
    (source / "keeper.txt").write_bytes(b"untouched source\n")
    code = textwrap.dedent(
        """
        import os
        import sys
        from pathlib import Path

        sys.path.insert(0, sys.argv[1])
        from diff_gremlin.acquisition.snapshots import acquire_source
        from diff_gremlin.acquisition import working_reads

        original_open = os.open
        replaced = False

        def replace_before_open(name, flags, *args, **kwargs):
            global replaced
            directory_fd = kwargs.get("dir_fd")
            if name == "race.txt" and directory_fd is not None and not replaced:
                os.unlink(name, dir_fd=directory_fd)
                os.mkfifo(name, dir_fd=directory_fd)
                replaced = True
                print("FIFO installed after regular-file stat", flush=True)
            return original_open(name, flags, *args, **kwargs)

        working_reads.os.open = replace_before_open
        try:
            with acquire_source(sys.argv[2], timeout=0.1):
                raise AssertionError("FIFO was delivered as a regular source file")
        except RuntimeError as error:
            assert "nonregular" in str(error), str(error)
            assert replaced, "race interception was not exercised"
            print("Rejected nonregular source", flush=True)
        """
    )
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", code, str(SOURCE), str(source)],
            env=child_environment,
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        )
    except subprocess.TimeoutExpired as error:
        pytest.fail(f"acquisition blocked on replaced FIFO despite deadline: {error.stdout!r}")
    assert result.returncode == 0, result.stderr
    assert "FIFO installed after regular-file stat" in result.stdout
    assert "Rejected nonregular source" in result.stdout
    assert stat.S_ISFIFO((source / "race.txt").stat().st_mode)
    assert (source / "keeper.txt").read_bytes() == b"untouched source\n"
    assert not list(Path(child_environment["TMPDIR"]).iterdir())


@pytest.mark.skipif(os.name != "posix", reason="requires surrogateescaped POSIX filenames")
@pytest.mark.parametrize("reverse", [False, True], ids=["added", "resolved"])
def test_cli_compare_preserves_nonutf8_filename_unicode_finding(
    repository, child_environment, reverse
):
    filename_bytes = b"direction-\xff.txt"
    filename = os.fsdecode(filename_bytes)
    path = repository / filename
    path.write_text("ordinary text\n", encoding="utf-8")
    git(repository, child_environment, "add", "--", filename)
    git(repository, child_environment, "commit", "-m", "ordinary filename bytes")
    base = git(repository, child_environment, "rev-parse", "HEAD")
    path.write_text("direction: \u202e\n", encoding="utf-8")
    git(repository, child_environment, "commit", "-am", "Unicode control")
    head = git(repository, child_environment, "rev-parse", "HEAD")
    before, after = (head, base) if reverse else (base, head)
    result = cli(
        repository,
        child_environment,
        "compare",
        str(repository),
        before,
        after,
        "--profile",
        "quick",
        "--timeout",
        "10",
        "--format",
        "json",
    )
    document = json.loads(result.stdout)
    assert document["mode"] == "comparison"
    assert document["comparison_base_sha"] == before
    assert document["base"]["source"]["commit_sha"] == before
    assert document["head"]["source"]["commit_sha"] == after
    delta = next(stage for stage in document["deltas"] if stage["id"] == "security.unicode")
    assert delta["comparable"]
    change = "resolved_findings" if reverse else "added_findings"
    opposite = "added_findings" if reverse else "resolved_findings"
    assert delta[opposite] == []
    assert len(delta[change]) == 1
    finding = delta[change][0]
    assert finding["rule"] == "unicode.bidi-control"
    assert finding["path"] == filename
    assert os.fsencode(finding["path"]) == filename_bytes
    assert finding["line"] == 1 and finding["symbol"] == "U+202E"
    side = "base" if reverse else "head"
    stage = next(s for s in document[side]["stages"] if s["id"] == "security.unicode")
    assert stage["findings"] == delta[change]


@pytest.mark.parametrize("output_format", ["text", "markdown"])
@pytest.mark.parametrize("mode", ["dirty", "clean", "commit", "no-git"])
def test_cli_human_source_labels_describe_scanned_bytes(
    repository, child_environment, tmp_path, output_format, mode
):
    anchor = git(repository, child_environment, "rev-parse", "HEAD")
    target = repository
    arguments = []
    if mode in {"dirty", "commit"}:
        (repository / "notes.txt").write_text("uncommitted text\n")
    if mode == "commit":
        arguments = ["--ref", anchor]
    elif mode == "no-git":
        target = tmp_path / "plain folder"
        target.mkdir()
        (target / "notes.txt").write_text("no Git anchor\n")
    result = cli(
        target,
        child_environment,
        "check",
        str(target),
        *arguments,
        "--profile",
        "quick",
        "--timeout",
        "10",
        "--format",
        output_format,
    )
    lines = result.stdout.splitlines()
    label = lines[1] if output_format == "text" else next(
        line for line in lines if line.startswith("Commit:")
    )
    if mode in {"dirty", "clean"}:
        assert "working tree" in label
        assert mode in label
        assert "HEAD anchor" in label and anchor in label
    elif mode == "commit":
        assert "commit " + anchor in label
        assert "working tree" not in label
    else:
        assert "working tree" in label and "no Git commit" in label
        assert anchor not in label
