"""Validate evidence emitted by controlled analysis drivers."""

import json
from typing import TypeGuard

from diff_gremlin.domain.context import SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.process import RunResult
from diff_gremlin.domain.stages import StageStatus


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


def _located_row(row: dict, paths: dict[str, str]) -> Finding:
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
    return Finding(
        rule=rule,
        message=f"Review {rule} diagnostic",
        severity=severity,
        path=paths[row["path"]],
        line=row["line"],
        column=row["column"],
    )


def located_findings(rows: list, files: tuple[SourceFile, ...]) -> list[Finding]:
    """Use generated messages because source diagnostics may contain credentials."""
    paths = {str(file.path.resolve()): file.relative_path for file in files}
    return [_located_row(row, paths) for row in rows]
