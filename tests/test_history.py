"""Controls for bounded, immutable, observable static Git history."""

import subprocess

import pytest
from test_python_analyzers import FakeRunner, make_context, native_runner

from diff_gremlin.analyzers.history import analyze_history
from diff_gremlin.analyzers.history_measure import source_observations
from diff_gremlin.domain.process import RunResult

_SHA = "a" * 40
_BLOB = "b" * 40


class HistoryRunner:
    def __init__(
        self, *, shallow=False, empty=False, content="def f():\n    return 1\n"
    ):
        self.shallow = shallow
        self.empty = empty
        self.content = content
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), kwargs))
        output, code = "", 0
        if "--version" in command:
            output = "git version 2.43.0"
        elif "--is-inside-work-tree" in command:
            output = "true\n"
        elif "--is-shallow-repository" in command:
            output = "true\n" if self.shallow else "false\n"
        elif "--verify" in command:
            output = "" if self.empty else _SHA + "\n"
            code = 1 if self.empty else 0
        elif "log" in command:
            output = f"{_SHA} 1234\n"
        elif "ls-tree" in command:
            output = f"100644 blob {_BLOB}\ta.py\x00"
        elif "cat-file" in command:
            output = f"{_BLOB} blob {len(self.content.encode())}\n{self.content}\n"
        return RunResult(tuple(command), code, output)


@pytest.mark.parametrize(
    "status,code",
    [
        ("missing", None),
        ("timeout", None),
        ("failed", None),
        ("output_limit", 0),
        ("ok", 2),
    ],
)
def test_history_failed_execution_is_unknown(tmp_path, status, code):
    result = analyze_history(make_context(tmp_path, FakeRunner("", code, status)))
    assert (
        result.status in ("missing", "timeout", "failed")
        and not result.metrics
        and not result.required
    )


def test_history_single_and_shallow_are_limited(tmp_path):
    runner = HistoryRunner()
    result = analyze_history(make_context(tmp_path, runner), limit=2, revision=_SHA)
    assert result.status == "limited" and result.metrics["commit_count"] == 1
    assert (
        result.metrics["rows"][0]["average_cc"] == 1.0
        and result.metrics["measure"] == "python-ast-decision-complexity-v1"
    )
    assert result.metrics["revision"] == _SHA and "One commit" in result.reason
    assert not any(
        "checkout" in command or "wily" in command for command, _ in runner.calls
    )
    result = analyze_history(make_context(tmp_path, HistoryRunner(shallow=True)))
    assert (
        result.status == "limited"
        and result.metrics["shallow"]
        and "Shallow" in result.reason
    )


def test_empty_repository_is_not_clean_history(tmp_path):
    stage = analyze_history(make_context(tmp_path, HistoryRunner(empty=True)))
    assert stage.status == "unsupported" and not stage.metrics


@pytest.mark.parametrize(
    "content", ["not valid python !!!", "def incomplete(", "\ufffd", "x = 1\x00"]
)
def test_invalid_historical_source_is_not_zero(tmp_path, content):
    stage = analyze_history(make_context(tmp_path, HistoryRunner(content=content)))
    assert stage.status == "failed" and not stage.metrics


@pytest.mark.parametrize("limit", [0, 51, -1, True, "10"])
def test_history_limit_validated_without_git(tmp_path, limit):
    runner = HistoryRunner()
    assert (
        analyze_history(make_context(tmp_path, runner), limit=limit).status == "failed"
    )
    assert not runner.calls


@pytest.mark.parametrize("revision", ["HEAD", "-x", "a" * 12, "z" * 40, True])
def test_history_rejects_ambiguous_revision_without_git(tmp_path, revision):
    runner = HistoryRunner()
    assert (
        analyze_history(make_context(tmp_path, runner), revision=revision).status
        == "failed"
    )
    assert not runner.calls


def test_named_function_ast_measure_does_not_double_count_nested_functions():
    source = """def outer(x):
    if x:
        return 1
    def inner(y):
        if y:
            return 2
        return 3
    return inner(x)
"""
    assert source_observations(source) == [2, 2]


def test_ast_measure_defined_decision_controls():
    source = """def choose(x):
    if x and x > 1:
        return [y for y in x if y]
    try:
        return 1 if x else 0
    except ValueError:
        return 3
"""
    assert source_observations(source) == [7]


def git(repo, *args):
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-C",
            str(repo),
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
        env={
            "PATH": "/usr/bin:/bin",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
        },
    )
    return result.stdout.strip()


def commit(repo, content):
    (repo / "a.py").write_text(content)
    git(repo, "add", "--", "a.py")
    git(repo, "commit", "-m", "controlled history fixture")
    return git(repo, "rev-parse", "HEAD")


def test_native_rising_stable_bounded_history_and_exact_revision(tmp_path):
    ctx = make_context(tmp_path, native_runner)
    git(ctx.root, "init", "--initial-branch=main")
    initial = commit(ctx.root, "def f(x):\n    return x\n")
    second = commit(ctx.root, "def f(x):\n    if x:\n        return 1\n    return 0\n")
    final = commit(ctx.root, "def f(x):\n    if x:\n        return 2\n    return 0\n")
    before = git(ctx.root, "status", "--porcelain")
    result = analyze_history(ctx, revision=final)
    assert result.status == "ok" and not result.required
    assert [row["commit"] for row in result.metrics["rows"]] == [initial, second, final]
    assert [row["max_cc"] for row in result.metrics["rows"]] == [1, 2, 2]
    assert [row["average_cc"] for row in result.metrics["rows"]] == [1.0, 2.0, 2.0]
    previous = analyze_history(ctx, limit=1, revision=second)
    assert (
        previous.metrics["rows"][0]["commit"] == second and previous.status == "limited"
    )
    assert (
        git(ctx.root, "rev-parse", "HEAD") == final
        and git(ctx.root, "status", "--porcelain") == before
    )
    assert not (ctx.root / ".wily").exists()


def test_native_empty_history(tmp_path):
    ctx = make_context(tmp_path, native_runner)
    git(ctx.root, "init", "--initial-branch=main")
    assert analyze_history(ctx).status == "unsupported"


def test_native_shallow_bare_history(tmp_path):
    ctx = make_context(tmp_path, native_runner)
    git(ctx.root, "init", "--initial-branch=main")
    commit(ctx.root, "def f(x):\n    return x\n")
    final = commit(ctx.root, "def f(x):\n    if x:\n        return 1\n    return 0\n")
    bare = tmp_path / "history.git"
    git(tmp_path, "clone", "--bare", "--depth=1", ctx.root.as_uri(), str(bare))
    result = analyze_history(ctx, bare, revision=final)
    assert (
        result.status == "limited"
        and result.metrics["shallow"]
        and result.metrics["commit_count"] == 1
    )
    assert result.metrics["rows"][0]["max_cc"] == 2


def test_native_historical_config_is_data(tmp_path):
    ctx = make_context(tmp_path, native_runner)
    git(ctx.root, "init", "--initial-branch=main")
    (ctx.root / "wily.cfg").write_text("[wily]\ncache_path = /unowned/location\n")
    (ctx.root / "setup.py").write_text('raise RuntimeError("must never execute")\n')
    git(ctx.root, "add", "--", "wily.cfg", "setup.py")
    commit(ctx.root, "def f(x):\n    return x\n")
    final = commit(ctx.root, "def f(x):\n    if x:\n        return 1\n    return 0\n")
    result = analyze_history(ctx, revision=final)
    assert result.status == "ok" and result.metrics["rows"][-1]["functions"] == 1


def test_real_runner_preserves_credential_shaped_source_blob(tmp_path):
    from diff_gremlin.process import run

    ctx = make_context(tmp_path, run)
    git(ctx.root, "init", "--initial-branch=main")
    source = 'def endpoint():\n    return "https://user:fake@example.invalid/path"\n'
    commit(ctx.root, source)
    final = commit(ctx.root, source + "# second immutable observation\n")
    result = analyze_history(ctx, revision=final)
    assert result.status == "ok" and result.metrics["commit_count"] == 2
    assert [row["max_cc"] for row in result.metrics["rows"]] == [1, 1]
