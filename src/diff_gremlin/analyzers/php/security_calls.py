"""Observe individual security rules for PHP call argument expressions."""

from dataclasses import dataclass

from diff_gremlin.analyzers.php.security_context import (
    allowed_unserialize,
    dynamic_shell,
    request_context,
)
from diff_gremlin.analyzers.php.security_findings import finding
from diff_gremlin.analyzers.php.token_expressions import arguments, global_call
from diff_gremlin.analyzers.php.token_model import PHPFileTokens, PHPToken
from diff_gremlin.domain.findings import Finding, Severity

_SHELL = {"exec", "system", "passthru", "shell_exec", "popen", "proc_open"}
_SQL = {"query", "exec", "raw", "unprepared"}


@dataclass(frozen=True, slots=True)
class CallContext:
    file: PHPFileTokens
    token: PHPToken
    name: str
    args: tuple[tuple[PHPToken, ...], ...]
    is_global: bool
    is_member: bool
    aliases: set[str]


def _unserialize(call: CallContext) -> list[Finding]:
    if not call.is_global or not request_context(call.args[0], call.aliases):
        return []
    if len(call.args) >= 2 and allowed_unserialize(call.args[1]):
        return []
    return [
        finding(
            call.file,
            call.token,
            "request-unserialize",
            "Request-context data passed to unserialize without a literal allowed_classes=false option; review object creation",
            "high",
        )
    ]


def _shell(call: CallContext) -> list[Finding]:
    if not call.is_global or not dynamic_shell(call.args[0]):
        return []
    return [
        finding(
            call.file,
            call.token,
            "dynamic-shell",
            "Dynamic shell command; verify argument escaping and input provenance",
            "high",
        )
    ]


def _extract(call: CallContext) -> list[Finding]:
    if not call.is_global:
        return []
    severity: Severity = (
        "high" if request_context(call.args[0], call.aliases) else "medium"
    )
    return [
        finding(
            call.file,
            call.token,
            "extract",
            "extract imports array keys into local variables; review key provenance and overwrite flags",
            severity,
        )
    ]


def _sql(call: CallContext) -> list[Finding]:
    if not call.is_member:
        return []
    expression = call.args[0]
    if not any(part.text == "." for part in expression):
        return []
    if not any(part.kind == "T_VARIABLE" for part in expression):
        return []
    return [
        finding(
            call.file,
            call.token,
            "concatenated-sql",
            "Concatenated dynamic raw query expression; review parameter binding",
            "medium",
        )
    ]


def _dispatch(call: CallContext) -> list[Finding]:
    if call.name == "unserialize":
        return _unserialize(call)
    if call.name == "extract":
        return _extract(call)
    if call.name in _SHELL and call.is_global:
        return _shell(call)
    if call.name in _SQL:
        return _sql(call)
    return []


def call_findings(
    file: PHPFileTokens, tokens: tuple[PHPToken, ...], index: int, aliases: set[str]
) -> list[Finding]:
    token = tokens[index]
    name = token.text.lower().lstrip("\\")
    if name not in _SHELL | _SQL | {"unserialize", "extract"}:
        return []
    args = arguments(tokens, index + 1)
    if not args:
        return []
    is_member = bool(index and tokens[index - 1].text in {"->", "?->", "::"})
    return _dispatch(
        CallContext(file, token, name, args, global_call(tokens, index), is_member, aliases)
    )
