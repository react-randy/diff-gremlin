"""Validate JSON evidence emitted by the controlled Node drivers."""

import json

from diff_gremlin.domain.context import SourceFile
from diff_gremlin.domain.findings import Finding


def natural(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def evidence(stdout: str, files: tuple[SourceFile, ...]) -> dict:
    """Require exactly the inventoried files, without accepting absent output."""
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


def located_findings(rows: list, files: tuple[SourceFile, ...]) -> list[Finding]:
    """Keep source text out of diagnostics and preserve repository locations."""
    paths = {str(file.path.resolve()): file.relative_path for file in files}
    findings = []
    for row in rows:
        if not isinstance(row, dict) or row.get("path") not in paths:
            raise ValueError("finding path outside requested inventory")
        line, column = row.get("line"), row.get("column")
        rule, severity = row.get("rule"), row.get("severity")
        if not natural(line) or line < 1 or not natural(column) or column < 1:
            raise ValueError("invalid finding location")
        if (
            not isinstance(rule, str)
            or not rule
            or severity not in {"info", "low", "medium", "high", "critical"}
        ):
            raise ValueError("invalid finding rule or severity")
        # Messages are generated here; parser output may contain credential literals.
        findings.append(
            Finding(
                rule=rule,
                message=f"Review {rule} diagnostic",
                severity=severity,
                path=paths[row["path"]],
                line=line,
                column=column,
            )
        )
    return findings
