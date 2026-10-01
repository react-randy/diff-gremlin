"""Observe command syntax without resolving aliases, functions or reachability."""

from pathlib import PurePosixPath

from diff_gremlin.analyzers.shell.walk import walk
from diff_gremlin.domain.findings import Finding, Severity

_INTERPRETERS = {"sh", "bash", "dash", "mksh", "ksh", "zsh"}
_BASH_LONG_FLAGS = {
    "--debug",
    "--debugger",
    "--dump-po-strings",
    "--dump-strings",
    "--help",
    "--login",
    "--noediting",
    "--noprofile",
    "--norc",
    "--posix",
    "--pretty-print",
    "--restricted",
    "--verbose",
    "--version",
}
_POSIX_FLAGS = frozenset("abCefhimnuvxrsco")
_BASH_FLAGS = _POSIX_FLAGS | frozenset("kptBCEHPTDlO")


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


def short_option_kind(option: str, interpreter: str) -> str:
    """Recognize known short flags and their named-option operands."""
    allowed = _BASH_FLAGS if interpreter == "bash" else _POSIX_FLAGS
    flags = set(option[1:])
    if not flags or not flags <= allowed:
        return "stop"
    if "c" in flags:
        return "command"
    return "operand" if flags & {"o", "O"} else "option"


def option_kind(option: str | None, interpreter: str) -> str:
    """Stop at script operands, separators and unknown option syntax."""
    if not option or option == "--" or option[:1] not in {"-", "+"}:
        return "stop"
    if option.startswith("--"):
        if interpreter == "bash" and option in {"--rcfile", "--init-file"}:
            return "operand"
        return (
            "option" if interpreter == "bash" and option in _BASH_LONG_FLAGS else "stop"
        )
    return short_option_kind(option, interpreter)


def command_string(args: list[dict], interpreter: str) -> bool:
    """Consume option operands without confusing them with a script operand."""
    remaining = iter(args)
    for arg in remaining:
        kind = option_kind(literal_parts(arg["Parts"]), interpreter)
        if kind == "command":
            return True
        if kind == "stop" or (kind == "operand" and next(remaining, None) is None):
            return False
    return False


def classification(args: list[dict]) -> tuple[str, Severity]:
    """Use operation labels only, preserving uncertainty in dynamic syntax."""
    name = literal_parts(args[0]["Parts"])
    if name is None:
        return "shell.dynamic-command", "info"
    if name == "eval":
        return "shell.eval", "high"
    interpreter = PurePosixPath(name).name
    if interpreter in _INTERPRETERS and command_string(args[1:], interpreter):
        return "shell.command-string", "high"
    if name in {"source", "."}:
        dynamic = len(args) < 2 or literal_parts(args[1]["Parts"]) is None
        return ("shell.dynamic-source", "info") if dynamic else ("shell.source", "info")
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
