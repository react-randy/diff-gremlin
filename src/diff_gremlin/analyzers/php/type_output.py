"""Accept located PHPStan diagnostics only from the exact owned source view."""

import json
from pathlib import Path

from diff_gremlin.analyzers.javascript.output import natural, positive
from diff_gremlin.domain.context import SourceFile
from diff_gremlin.domain.findings import Finding

UNRESOLVED = frozenset(
    {
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
        raise ValueError("PHPStan diagnostic is not an object")
    line, identifier = item.get("line"), item.get("identifier")
    if not positive(line) or line > lines:
        raise ValueError("PHPStan diagnostic location is outside copied source")
    if not isinstance(identifier, str) or not identifier or len(identifier) > 150:
        raise ValueError("PHPStan diagnostic has no valid rule identifier")
    if not isinstance(item.get("message"), str) or not isinstance(
        item.get("ignorable"), bool
    ):
        raise ValueError("PHPStan diagnostic schema differs")
    return Finding(
        "phpstan." + identifier,
        f"PHPStan {identifier} diagnostic (snapshot level 5)",
        "low" if identifier in UNRESOLVED else "medium",
        file.relative_path,
        line,
    )


def _output_rows(text: str) -> tuple[dict, dict]:
    data = json.loads(text)
    if not isinstance(data, dict) or not isinstance(data.get("totals"), dict):
        raise ValueError("PHPStan output has no totals")
    totals, rows, errors = data["totals"], data.get("files"), data.get("errors")
    if not isinstance(rows, dict) or not isinstance(errors, list):
        raise ValueError("PHPStan output has no file diagnostics or global errors")
    if errors or totals.get("errors") != 0 or not natural(totals.get("file_errors")):
        raise ValueError("PHPStan reported global analysis failures")
    return totals, rows


def _messages(value: object) -> list:
    if not isinstance(value, dict) or not isinstance(value.get("messages"), list):
        raise ValueError("PHPStan file diagnostic schema differs")
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
    if not isinstance(name, str) or Path(name) not in locations:
        raise ValueError("PHPStan reported a foreign source")
    path = Path(name)
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
