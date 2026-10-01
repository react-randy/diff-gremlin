"""Exercise the full image against a trusted read-only mixed-language control."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path


def invoke(
    image: str, arguments: list[str], mount: Path | None = None
) -> subprocess.CompletedProcess:
    """Run an image with the documented restricted local-analysis settings."""
    command = [
        "docker",
        "run",
        "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--network=none",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=1g",
    ]
    if mount:
        command.extend(["--mount", f"type=bind,src={mount},dst=/workspace,readonly"])
    return subprocess.run(
        [*command, image, *arguments], text=True, capture_output=True, timeout=300, check=False
    )


def check_doctor(image: str) -> None:
    """Require every bundled analyzer executable to be discoverable."""
    result = invoke(image, ["doctor", "--format", "json"])
    if result.returncode != 0:
        raise ValueError(f"Docker doctor failed ({result.returncode}): {result.stderr}")
    data = json.loads(result.stdout)
    missing = [name for name, facts in data["tools"].items() if not facts["available"]]
    if missing:
        raise ValueError(f"Docker doctor reports missing bundled tools: {', '.join(missing)}")


def write_control(root: Path) -> None:
    """Create only primary-authored source and metadata for the smoke test."""
    files = {
        "LICENSE": "MIT License\nCopyright 2026 Diff Gremlin contributors\n",
        "README.md": "# Controlled example\nA small fixture for trusted delivery validation.\n",
        ".gitignore": "__pycache__/\n",
        "example.py": "def add(left: int, right: int) -> int:\n    return left + right\n",
        "example.ts": "export function add(left: number, right: number): number {\n  return left + right;\n}\n",
        "Example.java": "public class Example { public static int add(int a, int b) { return a + b; } }\n",
        "tests/test_example.py": "def test_control():\n    assert 1 + 1 == 2\n",
        "package.json": '{"scripts":{"postinstall":"touch SHOULD_NOT_RUN"}}\n',
        "gradlew": "#!/bin/sh\ntouch SHOULD_NOT_RUN\n",
    }
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (root / "gradlew").chmod(0o755)
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
    root.chmod(0o755)


def checked_stages(data: dict) -> dict:
    """Require valid evidence and pinned versions from every bundled adapter."""
    stages = {stage["id"]: stage for stage in data["stages"]}
    expected = (
        "complexity.javascript",
        "python.lint.ruff",
        "python.types.pyrefly",
        "python.health.pyscn",
        "python.duplication.pyscn",
        "python.maintainability.radon",
        "javascript.lint.eslint",
        "typescript.types.tsc",
        "javascript.duplication.jscpd",
        "java.structure",
        "java.types",
        "security.secrets",
        "complexity.lizard",
    )
    failures = {
        name: stages.get(name, {}).get("status", "absent")
        for name in expected
        if stages.get(name, {}).get("status") != "ok"
    }
    if failures:
        raise ValueError(f"Docker control has invalid bundled analyzer evidence: {failures}")
    pinned_versions = {
        "python.lint.ruff": "0.16.8",
        "python.types.pyrefly": "1.3.0",
        "python.health.pyscn": "1.32.1",
        "python.maintainability.radon": "6.0.1",
        "javascript.lint.eslint": "10.11.0",
        "complexity.javascript": "10.11.0",
        "typescript.types.tsc": "6.0.3",
        "javascript.duplication.jscpd": "4.2.3",
        "security.secrets": "8.30.1",
        "complexity.lizard": "1.24.0",
    }
    wrong_versions = {
        name: stages[name].get("version")
        for name, version in pinned_versions.items()
        if stages[name].get("version") != version
    }
    if wrong_versions:
        raise ValueError(f"Docker control has unexpected analyzer versions: {wrong_versions}")
    return {name: stages[name] for name in expected}


def check_control(image: str) -> None:
    """Require valid full analyzer evidence without modifying source files."""
    with tempfile.TemporaryDirectory(prefix="diff gremlin control ") as directory:
        root = Path(directory)
        write_control(root)
        before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        result = invoke(
            image, ["check", "/workspace", "--format", "json", "--profile", "full"], root
        )
        if result.returncode not in (0, 1, 3):
            raise ValueError(f"Docker control failed ({result.returncode}): {result.stderr}")
        data = json.loads(result.stdout)
        stages = checked_stages(data)
        after = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        if before != after:
            raise ValueError("Docker control modified the mounted source")
        print(
            json.dumps(
                {
                    "profile": data["profile"],
                    "coverage": data["coverage"],
                    "assessment": data["assessment"],
                    "exit_code": result.returncode,
                    "versions": {name: stages[name]["version"] for name in stages},
                }
            )
        )


def main() -> int:
    """Validate one locally built image."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", nargs="?", default="diff-gremlin:ci")
    image = parser.parse_args().image
    help_result = invoke(image, ["--help"])
    if help_result.returncode != 0 or "check" not in help_result.stdout:
        parser.exit(1, f"Docker CLI help failed: {help_result.stderr}\n")
    try:
        check_doctor(image)
        check_control(image)
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Docker validation failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
