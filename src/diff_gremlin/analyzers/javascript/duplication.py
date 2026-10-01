"""Read only fresh jscpd evidence from an invocation-owned source view."""

import json
import math
import tempfile
from functools import partial
from pathlib import Path
from uuid import uuid4

from diff_gremlin.analyzers.javascript.installed import (
    installed_package,
    package_version,
    sibling_package,
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
_LIMITS = {"minLines": 5, "minTokens": 50, "maxLines": 1000, "maxSize": "100kb"}


def _percentage(total: dict) -> float:
    value = total.get("percentage")
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError("duplication percentage must be numeric")
    if not math.isfinite(value) or not 0 <= value <= 100:
        raise ValueError("invalid duplication percentage")
    return float(value)


def _inventory(value: object, expected: set[str], *, complete: bool = False) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(path, str) for path in value):
        raise TypeError("missing source inventory identities")
    observed = set(value)
    if len(observed) != len(value) or not observed <= expected:
        raise ValueError("source inventory differs from invocation")
    if complete and observed != expected:
        raise ValueError("requested inventory is incomplete")
    return observed


def _statistic_row(value: object) -> dict:
    if not isinstance(value, dict):
        raise TypeError("missing native source statistics")
    counters = ("sources", "clones", "lines", "tokens", "duplicatedLines", "duplicatedTokens")
    if not all(natural(value.get(key)) for key in counters):
        raise ValueError("invalid native source statistics")
    _percentage(value)
    _percentage({"percentage": value.get("percentageTokens")})
    return value


def _format_sources(value: object, expected: set[str]) -> set[str]:
    if not isinstance(value, dict) or not isinstance(value.get("sources"), dict):
        raise TypeError("missing per-format source identities")
    sources, total = value["sources"], _statistic_row(value.get("total"))
    if total["sources"] != len(sources) or not sources.keys() <= expected:
        raise ValueError("per-format source count or identities differ")
    for row in sources.values():
        if _statistic_row(row)["sources"] != 1:
            raise ValueError("invalid per-file source statistic")
    return set(sources)


def _source_ids(statistics: dict, expected: set[str]) -> set[str]:
    formats, total = statistics.get("formats"), statistics["total"]
    if not isinstance(formats, dict) or not natural(total.get("sources")):
        raise TypeError("missing native source-map statistics")
    identities, maps = set(), 0
    for name, value in formats.items():
        if name not in {"javascript", "typescript", "jsx", "tsx"}:
            raise ValueError("unexpected duplication source format")
        sources = _format_sources(value, expected)
        identities.update(sources)
        maps += len(sources)
    if maps != total["sources"]:
        raise ValueError("native source-map count differs from source identities")
    return identities


def _clone_location(location: object, paths: dict[str, str]) -> Finding:
    if not isinstance(location, dict) or not isinstance(location.get("name"), str):
        raise TypeError("invalid clone location")
    name = location["name"]
    if name not in paths or not Path(name).is_file() or not positive(location.get("start")):
        raise ValueError("clone location outside analyzed files")
    return Finding(
        "duplication.clone",
        "Duplicated block; review both clone locations",
        "low",
        paths[name],
        location["start"],
        1,
    )


def _clones(rows: list, paths: dict[str, str]) -> list[Finding]:
    findings = []
    for row in rows:
        if not isinstance(row, dict) or not natural(row.get("lines")):
            raise ValueError("invalid clone record")
        findings.extend(
            _clone_location(row.get(side), paths) for side in ("firstFile", "secondFile")
        )
    return findings


def _report_data(report_path: Path, expected: set[str], invocation: str):
    data = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("statistics"), dict):
        raise TypeError("missing duplication statistics")
    if data.get("invocation") != invocation or data.get("options") != _LIMITS:
        raise ValueError("duplication evidence belongs to different invocation or options")
    _inventory(data.get("requested_files"), expected, complete=True)
    detector = _inventory(data.get("detector_files"), expected)
    total, rows = _statistic_row(data["statistics"].get("total")), data.get("duplicates")
    if not isinstance(rows, list):
        raise TypeError("missing clone list")
    if total["clones"] != len(rows):
        raise ValueError("clone count differs from records")
    return data["statistics"], rows, detector


def _report(report_path: Path, paths: dict[str, str], invocation: str):
    statistics, rows, detector = _report_data(report_path, set(paths), invocation)
    identities = _source_ids(statistics, detector)
    total = statistics["total"]
    percentage = _percentage(total)
    if not identities and (percentage != 0 or rows):
        raise ValueError("duplication observations without native source identities")
    analyzed = {path: paths[path] for path in identities}
    metrics = {
        "duplication_percent": percentage,
        "clone_groups": len(rows),
        "analyzed_paths": sorted(analyzed.values()),
        "detector_input_files": len(detector),
        "native_source_maps": total["sources"],
        "minimum_clone_lines": _LIMITS["minLines"],
        "minimum_clone_tokens": _LIMITS["minTokens"],
        "maximum_file_lines": _LIMITS["maxLines"],
        "maximum_file_size": _LIMITS["maxSize"],
    }
    return metrics, _clones(rows, analyzed), len(analyzed)


def _copy_sources(files, source: Path) -> None:
    for file in files:
        destination = source / file.relative_path
        if not destination.resolve().is_relative_to(source.resolve()):
            raise ValueError("source inventory path escapes workspace")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(file.path.read_bytes())


def _observe(ctx, files, node, dependencies):
    with tempfile.TemporaryDirectory(prefix="jscpd-", dir=ctx.scratch) as directory:
        workspace = Path(directory)
        source = workspace / "source"
        source.mkdir()
        _copy_sources(files, source)
        paths = {str((source / file.relative_path).resolve()): file.relative_path for file in files}
        invocation = uuid4().hex
        config = workspace / "config.json"
        config.write_text(
            json.dumps({"files": list(paths), "invocation": invocation}), encoding="utf-8"
        )
        output = workspace / "output"
        result = ctx.run(
            [
                node,
                str(Path(__file__).parent / "assets" / "duplication.cjs"),
                *(str(package) for package in dependencies),
                str(config),
                "--output",
                str(output),
            ],
            cwd=workspace,
        )
        observations = (
            _report(output / "jscpd-report.json", paths, invocation) if valid_run(result) else None
        )
        return result, observations


def _environment(ctx):
    package = installed_package(ctx, "jscpd", "jscpd")
    node = trusted_executable(ctx, "node")
    if package is None or node is None:
        return None
    dependencies = tuple(
        sibling_package(package, name)
        for name in ("@jscpd/core", "@jscpd/tokenizer", "@jscpd/finder")
    )
    return (
        None
        if any(dependency is None for dependency in dependencies)
        else (package, node, dependencies)
    )


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
    package, node, dependencies = environment
    try:
        result, observations = _observe(ctx, files, node, dependencies)
        if observations is None:
            return absent(
                f"Controlled jscpd invocation {result.status}; exit {result.returncode}",
                status=failure_status(result),
            )
        metrics, findings, count = observations
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
        metrics=metrics,
        findings=findings,
        reason=""
        if count == len(files)
        else "jscpd native source identities cover fewer files than the selected inventory; "
        "native filters retain files with 5 to 1000 lines up to 100kb; clone windows require "
        "at least 5 lines and 50 tokens; omitted files do not supply a duplication score",
        eligible_files=len(files),
        analyzed_files=count,
        duration_seconds=result.duration_seconds,
    )
