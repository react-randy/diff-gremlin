"""Dispatch contextual observations while walking valid PHP parser tokens."""

import time

from diff_gremlin.analyzers.php.security_calls import call_findings
from diff_gremlin.analyzers.php.security_context import (
    dynamic_shell,
    request_aliases,
    request_context,
)
from diff_gremlin.analyzers.php.security_findings import finding
from diff_gremlin.analyzers.php.token_expressions import significant, statement
from diff_gremlin.analyzers.php.token_model import PHPFileTokens, PHPToken
from diff_gremlin.domain.findings import Finding, Severity

_INCLUDE = {"T_INCLUDE", "T_INCLUDE_ONCE", "T_REQUIRE", "T_REQUIRE_ONCE"}


def _include(
    file: PHPFileTokens, tokens: tuple[PHPToken, ...], index: int, aliases: set[str]
) -> list[Finding]:
    expression = statement(tokens, index + 1)
    # Parentheses surrounding a literal include are also a literal control.
    content = tuple(part for part in expression if part.text not in {"(", ")"})
    if content and all(
        part.kind in {"T_CONSTANT_ENCAPSED_STRING", "T_DIR", "T_FILE"} or part.text == "."
        for part in content
    ):
        return []
    severity: Severity = "high" if request_context(content, aliases) else "medium"
    return [
        finding(
            file,
            tokens[index],
            "variable-include",
            "Dynamic include/require path; review path allowlisting and input provenance",
            severity,
        )
    ]


def _backtick(
    file: PHPFileTokens, tokens: tuple[PHPToken, ...], start: int, end: int
) -> list[Finding]:
    if not dynamic_shell(tokens[start + 1 : end]):
        return []
    return [
        finding(
            file,
            tokens[start],
            "dynamic-shell",
            "Interpolated backtick shell command; verify argument escaping and input provenance",
            "high",
        )
    ]


def _token_findings(
    file: PHPFileTokens, tokens: tuple[PHPToken, ...], index: int, aliases: set[str]
) -> list[Finding]:
    token = tokens[index]
    if token.kind == "T_EVAL":
        return [
            finding(
                file,
                token,
                "eval",
                "eval parses executable code from an expression; review source provenance",
                "high",
            )
        ]
    if token.kind in _INCLUDE:
        return _include(file, tokens, index, aliases)
    if token.kind in {"T_STRING", "T_NAME_FULLY_QUALIFIED"}:
        return call_findings(file, tokens, index, aliases)
    return []


def observe_php_tokens(
    file: PHPFileTokens, *, deadline: float | None = None
) -> list[Finding]:
    tokens = significant(file.tokens)
    aliases = request_aliases(tokens)
    findings = []
    backtick: int | None = None
    for index, token in enumerate(tokens):
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("PHP security token time budget exhausted")
        findings.extend(_token_findings(file, tokens, index, aliases))
        if token.text == "`":
            if backtick is None:
                backtick = index
            else:
                findings.extend(_backtick(file, tokens, backtick, index))
                backtick = None
    return findings
