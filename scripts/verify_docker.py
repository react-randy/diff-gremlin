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
        [*command, image, *arguments],
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )


def check_doctor(image: str) -> None:
    """Require every bundled analyzer executable to be discoverable."""
    result = invoke(image, ["doctor", "--format", "json"])
    if result.returncode != 0:
        raise ValueError(f"Docker doctor failed ({result.returncode}): {result.stderr}")
    data = json.loads(result.stdout)
    missing = [name for name, facts in data["tools"].items() if not facts["available"]]
    if missing:
        raise ValueError(
            f"Docker doctor reports missing bundled tools: {', '.join(missing)}"
        )


def write_control(root: Path) -> None:
    """Create only primary-authored source and metadata for the smoke test."""
    files = {
        "LICENSE": "MIT License\nCopyright 2026 Diff Gremlin contributors\n",
        "README.md": "# Controlled example\nA small fixture for trusted delivery validation.\n",
        ".gitignore": "__pycache__/\n",
        "example.py": "def add(left: int, right: int) -> int:\n    return left + right\n",
        "example.ts": (
            "export function summarize(values: readonly number[]): {count: number; total: number; mean: number | null} {\n"
            "  const count = values.length;\n"
            "  const total = values.reduce((sum, value) => sum + value, 0);\n"
            "  const mean = count === 0 ? null : total / count;\n"
            "  return {count, total, mean};\n"
            "}\n"
        ),
        "Example.java": "public class Example { public static int add(int a, int b) { return a + b; } }\n",
        "tests/test_example.py": "def test_control():\n    assert 1 + 1 == 2\n",
        "package.json": '{"scripts":{"postinstall":"touch SHOULD_NOT_RUN"}}\n',
        "gradlew": "#!/bin/sh\ntouch SHOULD_NOT_RUN\n",
        "example.sh": "#!/bin/sh\nchoose() {\n  if [ \"$1\" = yes ]; then\n    printf '%s\\n' chosen\n  else\n    printf '%s\\n' skipped\n  fi\n}\n",
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
        "inventory",
        "hygiene",
        "security.unicode",
        "security.execution",
        "complexity.javascript",
        "shell.syntax.shfmt",
        "complexity.shell",
        "python.lint.ruff",
        "python.types.pyrefly",
        "python.health.pyscn",
        "python.deadcode.pyscn",
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
        raise ValueError(
            f"Docker control has invalid bundled analyzer evidence: {failures}"
        )
    if data.get("assessment", {}).get("complete") is not True:
        raise ValueError("Docker positive control requires complete selected evidence")
    pinned_versions = {
        "python.lint.ruff": "0.16.8",
        "python.types.pyrefly": "1.3.0",
        "python.health.pyscn": "1.32.1",
        "python.maintainability.radon": "6.0.1",
        "javascript.lint.eslint": "10.11.0",
        "complexity.javascript": "10.11.0",
        "shell.syntax.shfmt": "3.14.1",
        "complexity.shell": "3.14.1",
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
        raise ValueError(
            f"Docker control has unexpected analyzer versions: {wrong_versions}"
        )
    return {name: stages[name] for name in expected}


def check_control(image: str) -> None:
    """Require valid full analyzer evidence without modifying source files."""
    with tempfile.TemporaryDirectory(prefix="diff gremlin control ") as directory:
        root = Path(directory)
        write_control(root)
        before = {
            p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
        }
        result = invoke(
            image,
            ["check", "/workspace", "--format", "json", "--profile", "full"],
            root,
        )
        if result.returncode != 0:
            raise ValueError(
                f"Docker control failed ({result.returncode}): {result.stderr}"
            )
        data = json.loads(result.stdout)
        stages = checked_stages(data)
        after = {
            p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
        }
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


def check_short_receipt(result: subprocess.CompletedProcess) -> None:
    """Reject fabricated clone coverage or a hidden short-file limitation."""
    if result.returncode != 3:
        raise ValueError(
            f"Docker short-input coverage must exit3, got {result.returncode}"
        )
    data = json.loads(result.stdout)
    stage = next(s for s in data["stages"] if s["id"] == "javascript.duplication.jscpd")
    if (stage["status"], stage["analyzed_files"], stage["eligible_files"]) != (
        "limited",
        0,
        1,
    ):
        raise ValueError("Docker short-input clone coverage was fabricated or failed")
    if data["assessment"]["score"] is not None or not stage["reason"]:
        raise ValueError(
            "Docker short-input limitation must retain an unknown score and reason"
        )


def check_short_input(image: str) -> None:
    """Require explicit incomplete clone coverage below the native line window."""
    with tempfile.TemporaryDirectory(prefix="diff gremlin short control ") as directory:
        root = Path(directory)
        write_control(root)
        (root / "example.ts").write_text("export const answer: number = 42;\n")
        before = {
            p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
        }
        result = invoke(image, ["check", "/workspace", "--format", "json"], root)
        check_short_receipt(result)
        after = {
            p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
        }
        if before != after:
            raise ValueError("Docker short-input control modified mounted source")
        print(json.dumps({"short_input": "limited", "coverage": "0/1", "exit_code": 3}))


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
        check_short_input(image)
    except (ValueError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Docker validation failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
