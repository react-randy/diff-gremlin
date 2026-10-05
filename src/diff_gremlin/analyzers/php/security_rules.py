"""Produce contextual PHP execution observations from valid parser tokens."""

import time

from diff_gremlin.analyzers.php.security_context import (
    allowed_unserialize,
    dynamic_shell,
    request_aliases,
    request_context,
)
from diff_gremlin.analyzers.php.token_expressions import (
    arguments,
    global_call,
    significant,
    statement,
)
from diff_gremlin.analyzers.php.token_model import PHPFileTokens, PHPToken
from diff_gremlin.domain.findings import Finding, Severity

_SHELL = {"exec", "system", "passthru", "shell_exec", "popen", "proc_open"}
_INCLUDE = {"T_INCLUDE", "T_INCLUDE_ONCE", "T_REQUIRE", "T_REQUIRE_ONCE"}


def _finding(
    file: PHPFileTokens, token: PHPToken, rule: str, message: str, severity: Severity
) -> Finding:
    return Finding(
        f"security.php.{rule}",
        message,
        severity,
        file.source.relative_path,
        token.line,
        token.column,
        confidence="medium",
    )


def _call_findings(
    file: PHPFileTokens, tokens: tuple[PHPToken, ...], index: int, aliases: set[str]
) -> list[Finding]:
    token = tokens[index]
    name = token.text.lower().lstrip("\\")
    if name not in _SHELL | {"unserialize", "extract", "query", "raw", "unprepared"}:
        return []
    args = arguments(tokens, index + 1)
    if not args:
        return []
    first = args[0]
    is_global = global_call(tokens, index)
    if (
        is_global
        and name == "unserialize"
        and request_context(first, aliases)
        and (len(args) < 2 or not allowed_unserialize(args[1]))
    ):
        return [
            _finding(
                file,
                token,
                "request-unserialize",
                "Request-context data passed to unserialize without a literal allowed_classes=false option; review object creation",
                "high",
            )
        ]
    if is_global and name in _SHELL and dynamic_shell(first):
        return [
            _finding(
                file,
                token,
                "dynamic-shell",
                "Dynamic shell command; verify argument escaping and input provenance",
                "high",
            )
        ]
    if is_global and name == "extract":
        severity: Severity = "high" if request_context(first, aliases) else "medium"
        return [
            _finding(
                file,
                token,
                "extract",
                "extract imports array keys into local variables; review key provenance and overwrite flags",
                severity,
            )
        ]
    if (
        (
            name in {"query", "exec", "raw", "unprepared"}
            and index
            and tokens[index - 1].text in {"->", "?->", "::"}
        )
        and any(part.text == "." for part in first)
        and any(part.kind == "T_VARIABLE" for part in first)
    ):
        return [
            _finding(
                file,
                token,
                "concatenated-sql",
                "Concatenated dynamic raw query expression; review parameter binding",
                "medium",
            )
        ]
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
        if token.kind == "T_EVAL":
            findings.append(
                _finding(
                    file,
                    token,
                    "eval",
                    "eval parses executable code from an expression; review source provenance",
                    "high",
                )
            )
        elif token.kind in _INCLUDE:
            expression = statement(tokens, index + 1)
            # Parentheses surrounding a literal include are also a literal control.
            content = tuple(part for part in expression if part.text not in {"(", ")"})
            if not content or any(
                part.kind not in {"T_CONSTANT_ENCAPSED_STRING", "T_DIR", "T_FILE"}
                and part.text != "."
                for part in content
            ):
                severity: Severity = (
                    "high" if request_context(content, aliases) else "medium"
                )
                findings.append(
                    _finding(
                        file,
                        token,
                        "variable-include",
                        "Dynamic include/require path; review path allowlisting and input provenance",
                        severity,
                    )
                )
        elif token.kind in {"T_STRING", "T_NAME_FULLY_QUALIFIED"}:
            findings.extend(_call_findings(file, tokens, index, aliases))
        elif token.text == "`":
            if backtick is None:
                backtick = index
            else:
                if dynamic_shell(tokens[backtick + 1 : index]):
                    findings.append(
                        _finding(
                            file,
                            tokens[backtick],
                            "dynamic-shell",
                            "Interpolated backtick shell command; verify argument escaping and input provenance",
                            "high",
                        )
                    )
                backtick = None
    return findings
