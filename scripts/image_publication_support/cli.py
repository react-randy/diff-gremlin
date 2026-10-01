"""Route the fixed publication gates and report safe command failures."""

import argparse
import json
import sys
import urllib.error
from pathlib import Path

from . import identity, receipts, registry
from .policy import ARCHITECTURES, IMAGE


def parser() -> argparse.ArgumentParser:
    """Expose the fixed publication gates without arbitrary image or repository inputs."""
    result = argparse.ArgumentParser(
        description="Check the fixed Diff Gremlin release and its container publication receipts."
    )
    commands = result.add_subparsers(dest="command", required=True)
    guard = commands.add_parser("guard")
    guard.add_argument("--sha")
    guard.add_argument("--release-id")
    commands.add_parser("absent").add_argument(
        "--docker-config", type=Path, required=True
    )
    for name in ("receipt", "sources", "index"):
        command = commands.add_parser(name)
        command.add_argument("--sha", required=True)
        command.add_argument("--run-id", required=True)
        command.add_argument("--attempt", required=True)
        if name == "receipt":
            command.add_argument("--architecture", choices=ARCHITECTURES, required=True)
            command.add_argument("--platform", required=True)
            command.add_argument("--output", type=Path, required=True)
        else:
            command.add_argument("--receipts", type=Path, required=True)
    return result


def execute(args: argparse.Namespace) -> None:
    """Route one explicit publication gate."""
    if args.command == "guard":
        identity.guard(args.sha, args.release_id)
    elif args.command == "absent":
        registry.require_absent(args.docker_config)
    elif args.command == "receipt":
        receipt = receipts.pushed_receipt(
            args.architecture,
            args.sha,
            args.run_id,
            args.attempt,
            args.platform,
            json.load(sys.stdin),
        )
        receipts.write_receipt(args.output, receipt)
    else:
        proofs = receipts.read_receipts(
            args.receipts, args.sha, args.run_id, args.attempt
        )
        if args.command == "sources":
            for architecture in ARCHITECTURES:
                print(f"{IMAGE}@{proofs[architecture]}")
        else:
            receipts.validate_index(json.load(sys.stdin), proofs)
            print("Published index matches both validated native image receipts")


def main() -> int:
    """Exit visibly on failed identity, registry, receipt or index validation."""
    arguments = parser()
    try:
        execute(arguments.parse_args())
    except ValueError as error:
        arguments.exit(1, f"Image publication gate failed: {error}\n")
    except (KeyError, TypeError, OSError, urllib.error.URLError):
        arguments.exit(
            1, "Image publication gate failed: metadata unavailable or malformed\n"
        )
    return 0
