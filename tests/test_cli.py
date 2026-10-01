"""CLI intent, aliases, range errors and public help."""

import pytest

from diff_gremlin.cli.parser import normalize_legacy, parser


def test_default_and_legacy_targets():
    assert normalize_legacy([]) == ["check", "."]
    assert normalize_legacy(["folder"]) == ["check", "folder"]
    assert normalize_legacy(["--pr", "https://example/pull/1"]) == ["pr", "https://example/pull/1"]
    assert normalize_legacy(["folder", "--compare", "main", "HEAD"]) == [
        "compare",
        "folder",
        "main",
        "HEAD",
    ]


def test_review_quick_and_repo_full_defaults():
    assert parser().parse_args(["check"]).profile == "full"
    assert parser().parse_args(["pr", "https://example/pull/1"]).profile == "quick"


@pytest.mark.parametrize(
    "option,value",
    [("--timeout", "0"), ("--timeout", "nan"), ("--fail-under", "101"), ("--fail-under", "nan")],
)
def test_invalid_gate_numbers_fail_usage(option, value):
    with pytest.raises(SystemExit) as error:
        parser().parse_args(["check", option, value])
    assert error.value.code == 2


def test_help_names_real_workflows(capsys):
    with pytest.raises(SystemExit) as error:
        parser().parse_args(["--help"])
    assert error.value.code == 0
    output = capsys.readouterr().out
    assert all(command in output for command in ("check", "pr", "compare", "doctor", "policy"))
