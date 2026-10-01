"""Probe trusted tool availability without executing a target repository."""

import shutil
from pathlib import Path


def document() -> dict:
    from diff_gremlin.process import trusted_path

    search = trusted_path(Path.cwd())
    tools = (
        "git",
        "ruff",
        "pyrefly",
        "pyscn",
        "lizard",
        "gitleaks",
        "shfmt",
        "node",
        "eslint",
        "tsc",
        "jscpd",
        "java",
        "javac",
    )
    return {
        "tools": {
            tool: {"available": shutil.which(tool, path=search) is not None}
            for tool in tools
        },
        "guidance": [
            "Use the full Docker image for the bundled cross-language toolchain.",
            "Local Python full analysis also needs the optional PyScn platform wheel.",
            "No tools or target dependencies are installed during scanning.",
        ],
    }


def render(data: dict) -> str:
    rows = ["Diff Gremlin doctor"]
    rows.extend(
        f"{'available' if facts['available'] else 'missing':9} {tool}"
        for tool, facts in data["tools"].items()
    )
    return "\n".join(rows + [""] + data["guidance"]) + "\n"
