"""Accept located PHPStan diagnostics only from the exact owned source view."""

import json
import re
from pathlib import Path

from diff_gremlin.analyzers.javascript.output import natural, positive
from diff_gremlin.analyzers.php.type_identity import LEVEL
from diff_gremlin.domain.context import SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.runtime.environment import redact

_CONTEXT = re.compile(
    r"(.+) \(in context of class ([A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)*)\)\Z"
)


def _source_identity(name: object, locations: dict[Path, SourceFile]) -> Path:
    """Permit the observed trait context suffix only after exact copied-path identity."""
    if isinstance(name, str):
        direct = Path(name)
        if direct in locations:
            return direct
        context = _CONTEXT.fullmatch(name)
        if context and len(context.group(2)) <= 150:
            path = Path(context.group(1))
            if path in locations:
                return path
        # Name the rejected leaf without publishing temporary/host paths or
        # untrusted message text. The contextual suffix is descriptive only;
        # it can never supply another source path.
        prefix = name.split(" (", 1)[0]
        owned = locations.get(Path(prefix))
        label = owned.relative_path if owned else prefix
        description = (
            "unsupported context for inventoried source"
            if owned
            else "unrecognized source identity"
        )
        leaf = label.replace("\\", "/").rsplit("/", 1)[-1]
        leaf = redact(leaf[:100])
        leaf = re.sub(r"[A-Za-z0-9_=-]{24,}", "redacted", leaf)
        leaf = re.sub(r"[^A-Za-z0-9_.-]", "?", leaf)
        raise ValueError(
            f"PHPStan reported a foreign source ({description}: {leaf or 'unnamed'})"
        )
    raise ValueError("PHPStan reported a foreign source (non-string source identity)")


UNRESOLVED = frozenset(
    {
        "require.fileNotFound",
        "include.fileNotFound",
        "class.notFound",
        "interface.notFound",
        "trait.notFound",
        "function.notFound",
        "return.unresolvableType",
        "parameter.unresolvableType",
        "property.unresolvableType",
    }
)


def diagnostic(item: object, file: SourceFile, lines: int) -> Finding:
    """Keep source fragments private while returning the native rule and location."""
    if not isinstance(item, dict):
        raise TypeError("PHPStan diagnostic is not an object")
    line, identifier = item.get("line"), item.get("identifier")
    if not positive(line) or line > lines:
        raise ValueError("PHPStan diagnostic location is outside copied source")
    if (
        not isinstance(identifier, str)
        or len(identifier) > 150
        or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)*", identifier
        )
    ):
        raise ValueError("PHPStan diagnostic has no valid rule identifier")
    if not isinstance(item.get("message"), str) or not isinstance(
        item.get("ignorable"), bool
    ):
        raise TypeError("PHPStan diagnostic schema differs")
    return Finding(
        "phpstan." + identifier,
        f"PHPStan {identifier} diagnostic (snapshot level {LEVEL})",
        "low" if identifier in UNRESOLVED else "medium",
        file.relative_path,
        line,
    )


def _output_rows(text: str) -> tuple[dict, dict]:
    data = json.loads(text)
    if not isinstance(data, dict) or not isinstance(data.get("totals"), dict):
        raise TypeError("PHPStan output has no totals")
    totals, rows, errors = data["totals"], data.get("files"), data.get("errors")
    if not isinstance(rows, dict) or not isinstance(errors, list):
        raise TypeError("PHPStan output has no file diagnostics or global errors")
    if errors or totals.get("errors") != 0 or not natural(totals.get("file_errors")):
        raise ValueError("PHPStan reported global analysis failures")
    return totals, rows


def _messages(value: object) -> list:
    if not isinstance(value, dict) or not isinstance(value.get("messages"), list):
        raise TypeError("PHPStan file diagnostic schema differs")
    if not natural(value.get("errors")) or value["errors"] != len(value["messages"]):
        raise ValueError("PHPStan file counters disagree")
    return value["messages"]


def _source_lines(path: Path, file: SourceFile) -> int:
    with path.open("rb") as stream:
        source = stream.read(file.size_bytes + 1)
    if len(source) != file.size_bytes:
        raise ValueError("PHPStan copied source changed during analysis")
    return source.replace(b"\r\n", b"\n").replace(b"\r", b"\n").count(b"\n") + 1


def _source_findings(
    name: object, value: object, locations: dict[Path, SourceFile]
) -> list[Finding]:
    path = _source_identity(name, locations)
    file = locations[path]
    lines = _source_lines(path, file)
    return [diagnostic(item, file, lines) for item in _messages(value)]


def diagnostics(
    text: str, locations: dict[Path, SourceFile], returncode: int
) -> tuple[list[Finding], int]:
    """Reconcile native diagnostics, counters and exit status without clean defaults."""
    totals, rows = _output_rows(text)
    findings = [
        finding
        for name, value in rows.items()
        for finding in _source_findings(name, value, locations)
    ]
    if totals["file_errors"] != len(findings) or (returncode == 1) != bool(findings):
        raise ValueError(
            "PHPStan totals or exit code disagree with located diagnostics"
        )
    unresolved = sum(f.rule.removeprefix("phpstan.") in UNRESOLVED for f in findings)
    return findings, unresolved


def debug_document(text: str, locations: dict[Path, SourceFile]) -> str:
    """Require PHPStan debug's once-per-file progress before trusting completion."""
    prefix, separator, document = text.partition("{")
    progress = [line.strip() for line in prefix.splitlines() if line.strip()]
    expected = {str(path) for path in locations}
    if not separator or len(progress) != len(expected) or set(progress) != expected:
        raise ValueError(
            "PHPStan debug progress did not cover the exact source inventory"
        )
    return "{" + document


def type_metrics(findings: list[Finding], unresolved: int) -> dict:
    """Separate unavailable include paths from undefined snapshot symbols."""
    includes = sum(
        f.rule in {"phpstan.require.fileNotFound", "phpstan.include.fileNotFound"}
        for f in findings
    )
    return {
        "error_count": len(findings) - unresolved,
        "warning_count": unresolved,
        "unresolved_symbols": unresolved - includes,
        "unresolved_includes": includes,
        "level": LEVEL,
        "dependency_resolution": "source-only-static-reflection-no-vendor",
        "target_execution": False,
    }
