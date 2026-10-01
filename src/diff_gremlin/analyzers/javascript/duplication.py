"""Read only fresh jscpd evidence from an invocation-owned source view."""

import json
import math
import tempfile
from functools import partial
from pathlib import Path

from diff_gremlin.analyzers.javascript.installed import (
    installed_package,
    package_version,
    trusted_executable,
)
from diff_gremlin.analyzers.javascript.output import (
    failure_status,
    natural,
    positive,
    valid_run,
)
from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_ID, _LABEL = "javascript.duplication.jscpd", "JavaScript/TypeScript duplication"


def _percentage(total: dict) -> float:
    value = total.get("percentage")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError("duplication percentage must be numeric")
    if not math.isfinite(value) or not 0 <= value <= 100:
        raise ValueError("invalid duplication percentage")
    return float(value)


def _source_count(total: dict, eligible: int) -> int:
    sources = total.get("sources")
    if not positive(sources) or sources > eligible:
        raise ValueError("invalid analyzed file count")
    return sources


def _clone_location(location: object, source: Path) -> Finding:
    if not isinstance(location, dict) or not isinstance(location.get("name"), str):
        raise TypeError("invalid clone location")
    path = Path(location["name"])
    path = path if path.is_absolute() else source / path
    relative = path.resolve().relative_to(source.resolve())
    if not path.is_file() or not positive(location.get("start")):
        raise ValueError("clone location outside analyzed files")
    return Finding(
        "duplication.clone",
        "Duplicated block; review both clone locations",
        "low",
        str(relative),
        location["start"],
        1,
    )


def _clones(rows: list, source: Path) -> list[Finding]:
    findings = []
    for row in rows:
        if not isinstance(row, dict) or not natural(row.get("lines")):
            raise ValueError("invalid clone record")
        findings.extend(
            _clone_location(row.get(side), source) for side in ("firstFile", "secondFile")
        )
    return findings


def _report(report_path: Path, source: Path, eligible: int) -> tuple[float, list[Finding], int]:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("statistics"), dict):
        raise TypeError("missing duplication statistics")
    total, rows = data["statistics"].get("total"), data.get("duplicates")
    if not isinstance(total, dict) or not isinstance(rows, list):
        raise TypeError("missing total statistics or clone list")
    if not natural(total.get("clones")) or total["clones"] != len(rows):
        raise ValueError("clone count differs from records")
    return _percentage(total), _clones(rows, source), _source_count(total, eligible)


def _copy_sources(files, source: Path) -> None:
    for file in files:
        destination = source / file.relative_path
        if not destination.resolve().is_relative_to(source.resolve()):
            raise ValueError("source inventory path escapes workspace")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(file.path.read_bytes())


def _observe(ctx, files, node, binary):
    with tempfile.TemporaryDirectory(prefix="jscpd-", dir=ctx.scratch) as directory:
        workspace = Path(directory)
        source = workspace / "source"
        source.mkdir()
        _copy_sources(files, source)
        config = workspace / "config.json"
        config.write_text("{}", encoding="utf-8")
        output = workspace / "output"
        result = ctx.run(
            [
                node,
                binary,
                str(source),
                "--config",
                str(config),
                "--reporters",
                "json",
                "--output",
                str(output),
                "--format",
                "javascript,typescript,jsx,tsx",
                "--silent",
                "--absolute",
                "--noSymlinks",
                "--noTips",
            ],
            cwd=workspace,
        )
        observations = (
            _report(output / "jscpd-report.json", source, len(files)) if valid_run(result) else None
        )
        return result, observations


def _environment(ctx):
    package = installed_package(ctx, "jscpd", "jscpd")
    binary, node = trusted_executable(ctx, "jscpd"), trusted_executable(ctx, "node")
    if package is None or binary is None or node is None:
        return None
    return package, binary, node


def analyze_js_duplication(ctx: ScanContext) -> StageResult:
    files = tuple(
        file for file in ctx.production_files if file.language in {"javascript", "typescript"}
    )

    absent = partial(unavailable, _ID, _LABEL, "duplication", "jscpd", eligible_files=len(files))

    if not files:
        return absent("No JavaScript or TypeScript production files", status="skipped")
    environment = _environment(ctx)
    if environment is None:
        return absent("Installed trusted Node/jscpd package unavailable")
    package, binary, node = environment
    try:
        result, observations = _observe(ctx, files, node, binary)
        if observations is None:
            return absent(
                f"Controlled jscpd invocation {result.status}; exit {result.returncode}",
                status=failure_status(result),
            )
        percentage, findings, count = observations
    except (OSError, ValueError, TypeError):
        return absent(
            "jscpd report missing, unreadable, or schema/coverage invalid for this invocation",
            status="failed",
        )
    return StageResult(
        _ID,
        _LABEL,
        "duplication",
        "ok" if count == len(files) else "limited",
        "jscpd",
        package_version(package),
        metrics={"duplication_percent": percentage, "clone_groups": len(findings) // 2},
        findings=findings,
        reason=""
        if count == len(files)
        else "jscpd analyzed fewer files than the selected inventory",
        eligible_files=len(files),
        analyzed_files=count,
        duration_seconds=result.duration_seconds,
    )
