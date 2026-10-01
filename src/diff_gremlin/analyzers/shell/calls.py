"""Observe command syntax without resolving aliases, functions or reachability."""

from pathlib import PurePosixPath

from diff_gremlin.analyzers.shell.walk import walk
from diff_gremlin.domain.findings import Finding, Severity

_INTERPRETERS = {"sh", "bash", "dash", "mksh", "ksh", "zsh"}


def literal_part(part: dict) -> str | None:
    """Recognize only words with no expansion or escape interpretation."""
    kind = part["_kind"]
    if kind == "Lit":
        value = part.get("Value", "")
        return None if "\\" in value else value
    if kind == "SglQuoted" and not part.get("Dollar"):
        return part.get("Value", "")
    if kind == "DblQuoted" and not part.get("Dollar"):
        return literal_parts(part.get("Parts", []))
    return None


def literal_parts(parts: list[dict]) -> str | None:
    """Join static fragments internally; callers never publish argument values."""
    values = [literal_part(part) for part in parts]
    return (
        None
        if None in values
        else "".join(value for value in values if value is not None)
    )


def command_string(args: list[dict]) -> bool:
    """Recognize -c and combined short options before an operand or --."""
    for arg in args:
        option = literal_parts(arg["Parts"])
        if not option or option == "--" or not option.startswith("-"):
            return False
        if option == "--command" or (not option.startswith("--") and "c" in option[1:]):
            return True
    return False


def classification(args: list[dict]) -> tuple[str, Severity]:
    """Use operation labels only, preserving uncertainty in dynamic syntax."""
    name = literal_parts(args[0]["Parts"])
    if name is None:
        return "shell.dynamic-command", "low"
    if name == "eval":
        return "shell.eval", "high"
    if PurePosixPath(name).name in _INTERPRETERS and command_string(args[1:]):
        return "shell.command-string", "high"
    if name in {"source", "."}:
        dynamic = len(args) < 2 or literal_parts(args[1]["Parts"]) is None
        return ("shell.dynamic-source", "low") if dynamic else ("shell.source", "info")
    return "shell.command-call", "info"


def call_findings(tree: dict, path: str) -> list[Finding]:
    """Emit each actual command call, including calls nested in substitutions."""
    findings = []
    for node in walk(tree):
        if node["_kind"] != "CallExpr" or not node.get("Args"):
            continue
        rule, severity = classification(node["Args"])
        findings.append(
            Finding(
                rule,
                "Review Shell command syntax; aliases, expansions, function identity and reachability are unresolved",
                severity,
                path,
                node["Args"][0]["Pos"]["Line"],
                node["Args"][0]["Pos"]["Col"],
                confidence="medium" if severity == "high" else "low",
            )
        )
    return findings
