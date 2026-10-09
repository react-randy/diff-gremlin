"""Validate evidence emitted by controlled analysis drivers."""

import json
import re
import unicodedata
from typing import TypeGuard

from diff_gremlin.analyzers.javascript.coordinates import (
    CoordinateKind,
    SourceCoordinates,
)
from diff_gremlin.domain.context import SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.process import RunResult
from diff_gremlin.domain.stages import StageStatus
from diff_gremlin.runtime.environment import redact

_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"|`[^`]*`")
_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*\Z")
_NAME_CONTEXT = re.compile(
    r"(?:[Pp]arameter|[Pp]roperty|[Nn]ame|[Mm]odule|[Nn]amespace|[Mm]ember|[Cc]lass|[Ii]nterface) $"
)
_MODULE = re.compile(r"(?:@[a-zA-Z0-9_-]+/)?[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*\Z")
_PROSE_MARKUP = re.compile(
    r"(\[path\]|\[redacted\])|<[^>]*>|\[[^\]]*\]|[<>\[\]`*_#|\\]"
)
_PRIMITIVES = frozenset(
    {
        "string",
        "number",
        "boolean",
        "bigint",
        "symbol",
        "object",
        "any",
        "unknown",
        "never",
        "void",
        "undefined",
        "null",
    }
)


def diagnostic_message(value: object) -> str:
    """Retain compiler prose and safe name contexts without publishing literals."""
    if not isinstance(value, str) or not value:
        raise ValueError("missing native diagnostic message")
    # Bound work before looking at untrusted source fragments. Credential and
    # path filtering precede bounded, single-line evidence.
    text = redact(value[:4096])
    text = re.sub(r"(?<![A-Za-z0-9_@.-])(?:[A-Za-z]:[\\/]|/)[^\s'\"`]+", "[path]", text)
    text = re.sub(r"\b[A-Za-z0-9_=-]{24,}\b", "[redacted]", text)
    text = re.sub(
        r"(?:\b|_)(?:gh[pousr]_|github_pat_|sk[-_]|AKIA)[A-Za-z0-9_-]*",
        "[redacted]",
        text,
        flags=re.IGNORECASE,
    )
    quoted_parts = list(_QUOTED.finditer(text))
    if _unsafe_quoting(text, quoted_parts):
        return "Native diagnostic text withheld because quoting was unsafe"

    def quoted(match: re.Match[str]) -> str:
        content = match.group()[1:-1]
        prefix = text[: match.start()]
        name = (
            (
                bool(_NAME_CONTEXT.search(prefix))
                or prefix.endswith(" does not exist on type ")
            )
            and bool(_IDENTIFIER.fullmatch(content))
            and len(content) <= 80
        )
        module = (
            prefix.endswith("module ")
            and bool(_MODULE.fullmatch(content))
            and len(content) <= 100
            and ".." not in content.split("/")
        )
        primitive = content in _PRIMITIVES
        return match.group() if name or module or primitive else "'[redacted]'"

    parts, start = [], 0
    for match in quoted_parts:
        parts.extend((_diagnostic_prose(text[start : match.start()]), quoted(match)))
        start = match.end()
    parts.append(_diagnostic_prose(text[start:]))
    # Evidence stays format-neutral. Quoted identifier grammar preserves safe
    # underscores; unquoted markup is withheld, rather than presentation-escaped.
    text = "".join(parts)
    text = "".join(
        " " if unicodedata.category(char).startswith("C") else char for char in text
    )
    return " ".join(text.split())[:512]


def _diagnostic_prose(text: str) -> str:
    return _PROSE_MARKUP.sub(lambda match: match.group(1) or "[redacted]", text)


def _unsafe_quoting(text: str, parts: list[re.Match[str]]) -> bool:
    if any(char in _QUOTED.sub("", text) for char in "'\"`"):
        return True
    return any(
        any(char in match.group()[1:-1] for char in "'\"`")
        or any(
            char.isalnum() or char in "_$'\"`"
            for char in text[max(0, match.start() - 1) : match.start()]
            + text[match.end() : match.end() + 1]
        )
        for match in parts
    )


def natural(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def positive(value: object) -> TypeGuard[int]:
    return natural(value) and value > 0


def valid_run(result: RunResult, codes: tuple[int, ...] = (0,)) -> bool:
    return result.status == "ok" and result.returncode in codes


def failure_status(result: RunResult) -> StageStatus:
    return result.status if result.status in {"missing", "timeout"} else "failed"


def evidence(stdout: str, files: tuple[SourceFile, ...]) -> dict:
    data = json.loads(stdout)
    if not isinstance(data, dict) or not isinstance(data.get("files"), list):
        raise TypeError("expected object with file evidence")
    expected = {str(file.path.resolve()) for file in files}
    observed = data["files"]
    if len(observed) != len(expected) or set(observed) != expected:
        raise ValueError("reported files differ from requested inventory")
    if not isinstance(data.get("findings"), list):
        raise TypeError("missing located findings")
    return data


def _located_row(
    row: dict,
    paths: dict[str, str],
    coordinates: SourceCoordinates,
    kind: CoordinateKind,
    native_messages: bool,
) -> Finding:
    if not isinstance(row, dict) or row.get("path") not in paths:
        raise ValueError("finding path outside requested inventory")
    if not positive(row.get("line")) or not positive(row.get("column")):
        raise ValueError("invalid finding location")
    rule, severity = row.get("rule"), row.get("severity")
    if (
        not isinstance(rule, str)
        or not rule
        or severity not in {"info", "low", "medium", "high", "critical"}
    ):
        raise ValueError("invalid finding rule or severity")
    native_kind = "javac" if kind == "jdk" and rule == "java.syntax" else kind
    coordinates.validate(row["path"], row["line"], row["column"], native_kind)
    return Finding(
        rule=rule,
        message=diagnostic_message(row.get("message"))
        if native_messages
        else f"Review {rule} diagnostic",
        severity=severity,
        path=paths[row["path"]],
        line=row["line"],
        column=row["column"],
    )


def located_findings(
    rows: list,
    files: tuple[SourceFile, ...],
    *,
    kind: CoordinateKind = "javascript",
    native_messages: bool = False,
) -> list[Finding]:
    """Default to generated messages; explicitly requested native text is sanitized."""
    paths = {str(file.path.resolve()): file.relative_path for file in files}
    coordinates = SourceCoordinates(files)
    return [
        _located_row(row, paths, coordinates, kind, native_messages) for row in rows
    ]
