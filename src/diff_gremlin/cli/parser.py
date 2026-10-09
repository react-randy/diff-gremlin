"""Discoverable commands, meaningful defaults and explicit CI gates."""

import argparse

from diff_gremlin import __version__


def bounded_number(value: str) -> float:
    parsed = float(value)
    if not 0 <= parsed <= 100:
        raise argparse.ArgumentTypeError("score must be between 0 and 100")
    return parsed


def positive_seconds(value: str) -> float:
    parsed = float(value)
    if not 0 < parsed <= 3600:
        raise argparse.ArgumentTypeError(
            "timeout must be greater than 0 and at most 3600 seconds"
        )
    return parsed


def common_options(parser, *, profile="full", comparison=False):
    parser.add_argument(
        "--profile",
        choices=("quick", "full"),
        default=profile,
        help=f"quick omits clone/health/history analysis; default: {profile}",
    )
    parser.add_argument(
        "--format",
        choices=("text", "markdown", "json", "json-delta")
        if comparison
        else ("text", "markdown", "json"),
        default="text",
        help="text/markdown show top findings; json contains complete receipts"
        + ("; json-delta omits snapshot arrays" if comparison else ""),
    )
    parser.add_argument(
        "--quiet", action="store_true", help="suppress stage progress on stderr"
    )
    parser.add_argument(
        "--timeout",
        type=positive_seconds,
        default=120.0,
        metavar="SECONDS",
        help="deadline per external analyzer/acquisition (default: 120)",
    )
    parser.add_argument(
        "--fail-under",
        type=bounded_number,
        metavar="SCORE",
        help="exit 1 below SCORE; unknown evidence exits 3",
    )
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        help="exit 1 for findings at this severity or above",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="make complete-evidence intent explicit; incomplete already exits 3",
    )


def comparison_options(command) -> None:
    command.add_argument(
        "--paths",
        action="append",
        default=[],
        metavar="PATH",
        help="scan only this literal repository-relative file/subtree (repeatable); marks evidence partial",
    )
    command.add_argument(
        "--changed-paths",
        action="store_true",
        help="scan only paths changed between supplied refs; intersects --paths; marks evidence partial",
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="diff-gremlin",
        description="Static risk checks for repos and pull requests. Findings, coverage, and receipts.",
        epilog="Examples: diff-gremlin check . | diff-gremlin pr URL --format json | diff-gremlin doctor\nExits: 0 complete, 1 gate failure, 2 operational/usage error, 3 incomplete evidence.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    root.add_argument(
        "--version", action="version", version=f"diff-gremlin {__version__}"
    )
    commands = root.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="inspect a local folder or Git HTTPS URL")
    check.add_argument(
        "target",
        nargs="?",
        default=".",
        help="folder or repository HTTPS URL (default: current folder)",
    )
    check.add_argument(
        "--ref",
        help="scan an immutable Git snapshot at this ref instead of local current files",
    )
    common_options(check)
    pr = commands.add_parser(
        "pr", help="compare immutable GitHub PR or GitLab MR snapshots"
    )
    pr.add_argument("url", help="GitHub /pull/N or GitLab /-/merge_requests/N URL")
    common_options(pr, profile="quick", comparison=True)
    comparison_options(pr)
    compare = commands.add_parser(
        "compare", help="compare two refs without changing your checkout"
    )
    compare.add_argument("target", help="local Git folder or repository HTTPS URL")
    compare.add_argument("base", help="base ref or full SHA")
    compare.add_argument("head", help="head ref or full SHA")
    common_options(compare, comparison=True)
    comparison_options(compare)
    doctor = commands.add_parser(
        "doctor",
        help="show installed capabilities and actionable missing-tool guidance",
    )
    doctor.add_argument("--format", choices=("text", "json"), default="text")
    commands.add_parser(
        "policy", help="print the versioned score policy and exit semantics"
    )
    return root


def normalize_legacy(arguments: list[str]) -> list[str]:
    """Keep documented v0 positional/--pr/--compare usage as small aliases."""
    if not arguments:
        return ["check", "."]
    if arguments[0] == "--pr":
        return ["pr", *arguments[1:]]
    if "--compare" in arguments:
        index = arguments.index("--compare")
        target = arguments[0] if index else "."
        tail = arguments[index + 1 :]
        return ["compare", target, *tail]
    known = {"check", "pr", "compare", "doctor", "policy", "--help", "-h", "--version"}
    return arguments if arguments[0] in known else ["check", *arguments]
