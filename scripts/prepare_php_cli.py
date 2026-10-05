"""Wrap an already trusted system PHP with explicit extensions and no php.ini."""

import argparse
import json
import shlex
import subprocess
import tempfile
from pathlib import Path

PROBE = (
    "echo json_encode(['version'=>PHP_VERSION,'directory'=>ini_get('extension_dir'),"
    "'tokenizer'=>function_exists('token_get_all'),'phar'=>class_exists('Phar')]);"
)


def facts(command: list[str]) -> dict:
    """Probe scanner-owned literals from a neutral directory, never source files."""
    with tempfile.TemporaryDirectory(prefix="php-runtime-probe-") as directory:
        result = subprocess.run(
            [*command, "-r", PROBE],
            cwd=directory,
            env={"PATH": "/usr/bin:/bin"},
            text=True,
            capture_output=True,
            timeout=15,
            check=True,
        )
    data = json.loads(result.stdout)
    if not isinstance(data, dict) or not isinstance(data.get("directory"), str):
        raise TypeError("PHP runtime probe returned an invalid identity")
    return data


def prepare(binary: Path, destination: Path) -> dict:
    """Enable only required native extensions from the trusted runtime directory."""
    binary = binary.resolve(strict=True)
    destination = destination.absolute()
    if destination.resolve() == binary:
        raise ValueError("Refusing to overwrite the system PHP executable")
    command = [str(binary), "-n"]
    data = facts(command)
    for extension in ("tokenizer", "phar"):
        if not data.get(extension):
            path = (Path(data["directory"]) / f"{extension}.so").resolve(strict=True)
            if not path.is_relative_to(Path(data["directory"]).resolve()):
                raise ValueError("Required PHP extension escapes its trusted directory")
            command.extend(["-d", f"extension={path}"])
    verified = facts(command)
    if not all(verified.get(name) is True for name in ("tokenizer", "phar")):
        raise ValueError("PHP tokenizer and PHAR are required without php.ini")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
    destination.chmod(0o755)
    return verified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Already trusted PHP CLI executable")
    parser.add_argument("destination", type=Path, help="Private wrapper path")
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.binary, args.destination)))
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"PHP runtime preparation failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
