"""Probe trusted tool availability without executing a target repository."""

import shutil


def document() -> dict:
    from diff_gremlin.process import trusted_path

    search = trusted_path()
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
        "php",
        "phpstan.phar",
    )
    return {
        "tools": {
            tool: {"available": shutil.which(tool, path=search) is not None}
            for tool in tools
        },
        "guidance": [
            "Use the full Docker image for the bundled cross-language toolchain.",
            "Local Python full analysis also needs the optional PyScn platform wheel.",
            "PHP uses a trusted CLI tokenizer and the verified standalone PHPStan 2.2.15 PHAR at snapshot level 5; no Composer or Laravel bootstrap.",
            "PHP CLI must expose tokenizer and PHAR with -n (no php.ini); the full Docker image supplies both.",
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
