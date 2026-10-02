"""Read only fresh jscpd evidence from an invocation-owned source view."""

import json
import tempfile
from functools import partial
from pathlib import Path
from uuid import uuid4

from diff_gremlin.analyzers.javascript.duplication_statistics import (
    format_catalog,
    percentage,
    source_ids,
    statistic_row,
)
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
_MAX_REPORT_BYTES = 4 * 1024 * 1024
_MAX_SOURCE_BYTES = 100 * 1024


class CloneCoordinateError(ValueError):
    """A well-formed native clone location disagrees with captured source."""


def _inventory(
    value: object, expected: set[str], *, complete: bool = False
) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(path, str) for path in value):
        raise TypeError("missing source inventory identities")
    observed = set(value)
    if len(observed) != len(value) or not observed <= expected:
        raise ValueError("source inventory differs from invocation")
    if complete and observed != expected:
        raise ValueError("requested inventory is incomplete")
    return observed


def _source_lengths(name: str) -> tuple[int, ...]:
    with Path(name).open("rb") as stream:
        contents = stream.read(_MAX_SOURCE_BYTES + 1)
    if len(contents) > _MAX_SOURCE_BYTES:
        raise ValueError("clone source exceeds native file size limit")
    # Native tokenizer columns count UTF-16 units; only LF advances its line counter.
    lines = contents.decode("utf-8", errors="replace").split("\n")
    return tuple(len(line.encode("utf-16-le")) // 2 for line in lines)


def _clone_point(point: object, line: int) -> dict:
    if (
        not isinstance(point, dict)
        or not positive(point.get("line"))
        or point.get("line") != line
    ):
        raise ValueError("clone endpoint differs from reported line")
    if not positive(point.get("column")) or not natural(point.get("position")):
        raise ValueError("invalid clone endpoint")
    return point


def _clone_schema(location: object, paths: dict[str, str]) -> dict:
    """Malformed or foreign records never become recognized native defects."""
    if not isinstance(location, dict) or not isinstance(location.get("name"), str):
        raise TypeError("invalid clone location")
    if location["name"] not in paths:
        raise ValueError("clone location outside analyzed files")
    start, end = location.get("start"), location.get("end")
    if not positive(start) or not positive(end):
        raise ValueError("invalid clone line extent")
    _clone_point(location.get("startLoc"), start)
    _clone_point(location.get("endLoc"), end)
    return location


def _clone_range(location: dict, lengths: tuple[int, ...]) -> None:
    start, end = location["start"], location["end"]
    if not 1 <= start <= end <= len(lengths):
        raise CloneCoordinateError("clone range outside source lines")
    first, last = location["startLoc"], location["endLoc"]
    if any(point["column"] > lengths[point["line"] - 1] + 1 for point in (first, last)):
        raise CloneCoordinateError("clone column outside source line")
    if (start, first["column"]) > (end, last["column"]):
        raise CloneCoordinateError("reversed clone endpoints")
    if first["position"] > last["position"]:
        raise CloneCoordinateError("reversed native clone positions")


def _clone_location(
    location: object, paths: dict[str, str], lengths: dict[str, tuple[int, ...]]
) -> Finding:
    location = _clone_schema(location, paths)
    name = location["name"]
    _clone_range(location, lengths[name])
    return Finding(
        "duplication.clone",
        "Duplicated block; review both clone locations",
        "low",
        paths[name],
        location["start"],
        1,
    )


def _clones(rows: list, paths: dict[str, str]) -> tuple[list[Finding], dict[str, int]]:
    findings, rejected = [], {}
    lengths = {name: _source_lengths(name) for name in paths} if rows else {}
    for row in rows:
        if not isinstance(row, dict) or not positive(row.get("lines")):
            raise ValueError("invalid clone record")
        first = _clone_schema(row.get("firstFile"), paths)
        second = _clone_schema(row.get("secondFile"), paths)
        if row["lines"] != first["end"] - first["start"] + 1:
            raise ValueError("clone extent differs from first source range")
        # RabinKarp.enlargeClone may replace B.end using a different hash-hit source.
        # A remains the scanned source: only well-formed B coordinate defects degrade.
        first_finding = _clone_location(first, paths, lengths)
        try:
            second_finding = _clone_location(second, paths, lengths)
        except CloneCoordinateError as error:
            cause = str(error)
            rejected[cause] = rejected.get(cause, 0) + 1
            continue
        findings.extend((first_finding, second_finding))
    return findings, rejected


def _report_data(report_path: Path, expected: set[str], invocation: str):
    with report_path.open("rb") as stream:
        contents = stream.read(_MAX_REPORT_BYTES + 1)
    if len(contents) > _MAX_REPORT_BYTES:
        raise ValueError("duplication report exceeds evidence size limit")
    data = json.loads(contents)
    if not isinstance(data, dict) or not isinstance(data.get("statistics"), dict):
        raise TypeError("missing duplication statistics")
    if data.get("invocation") != invocation or data.get("options") != _LIMITS:
        raise ValueError(
            "duplication evidence belongs to different invocation or options"
        )
    _inventory(data.get("requested_files"), expected, complete=True)
    detector = _inventory(data.get("detector_files"), expected)
    total, rows = (
        statistic_row(data["statistics"].get("total")),
        data.get("duplicates"),
    )
    if not isinstance(rows, list):
        raise TypeError("missing clone list")
    if total["clones"] != len(rows):
        raise ValueError("clone count differs from records")
    return (
        data["statistics"],
        rows,
        detector,
        format_catalog(data.get("tokenizer_formats")),
    )


def _report(report_path: Path, paths: dict[str, str], invocation: str):
    statistics, rows, detector, catalog = _report_data(
        report_path, set(paths), invocation
    )
    identities = source_ids(statistics, detector, rows, catalog)
    total = statistics["total"]
    ratio = percentage(total.get("percentage"))
    if not identities and (ratio != 0 or rows):
        raise ValueError("duplication observations without native source identities")
    analyzed = {path: paths[path] for path in identities}
    metrics = {
        "duplication_percent": ratio,
        "measure": "jscpd-native-clone-incidence-v1",
        "clone_groups": len(rows),
        "analyzed_paths": sorted(analyzed.values()),
        "detector_input_files": len(detector),
        "native_source_maps": total["sources"],
        "minimum_clone_lines": _LIMITS["minLines"],
        "minimum_clone_tokens": _LIMITS["minTokens"],
        "maximum_file_lines": _LIMITS["maxLines"],
        "maximum_file_size": _LIMITS["maxSize"],
    }
    findings, rejected = _clones(rows, analyzed)
    if rejected:
        metrics["native_duplication_incidence_percent"] = metrics.pop(
            "duplication_percent"
        )
        count = sum(rejected.values())
        metrics["verified_clone_groups"] = len(rows) - count
        metrics["rejected_clone_groups"] = count
        metrics["rejected_clone_reasons"] = dict(sorted(rejected.items()))
    return metrics, findings, len(analyzed)


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
        paths = {
            str((source / file.relative_path).resolve()): file.relative_path
            for file in files
        }
        invocation = uuid4().hex
        config = workspace / "config.json"
        config.write_text(
            json.dumps({"files": list(paths), "invocation": invocation}),
            encoding="utf-8",
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
            _report(output / "jscpd-report.json", paths, invocation)
            if valid_run(result)
            else None
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


def _coverage_reason(metrics: dict, count: int, eligible: int) -> str:
    """Explain both native input omissions and rejected native clone coordinates."""
    reasons = []
    if count < eligible:
        reasons.append(
            "jscpd native source identities cover fewer files than the selected inventory; "
            "native filters retain files with 5 to 1000 lines up to 100kb; clone windows require "
            "at least 5 lines and 50 tokens; omitted files do not supply a duplication score"
        )
    if rejected := metrics.get("rejected_clone_groups"):
        reasons.append(
            f"jscpd upstream native coordinate defect rejected {rejected} clone groups; "
            + ", ".join(metrics["rejected_clone_reasons"])
            + "; "
            + "verified clone findings remain, but native incidence telemetry supplies no duplication score"
        )
    return "; ".join(reasons)


def analyze_js_duplication(ctx: ScanContext) -> StageResult:
    files = tuple(
        file
        for file in ctx.production_files
        if file.language in {"javascript", "typescript"}
    )

    absent = partial(
        unavailable, _ID, _LABEL, "duplication", "jscpd", eligible_files=len(files)
    )

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
    except OSError:
        return absent(
            "jscpd evidence could not be read; source/report paths are omitted",
            status="failed",
        )
    except (ValueError, TypeError) as error:
        return absent(f"jscpd native evidence invalid: {error}", status="failed")
    return StageResult(
        _ID,
        _LABEL,
        "duplication",
        "ok"
        if count == len(files) and not metrics.get("rejected_clone_groups")
        else "limited",
        "jscpd",
        package_version(package),
        metrics=metrics,
        findings=findings,
        reason=_coverage_reason(metrics, count, len(files)),
        eligible_files=len(files),
        analyzed_files=count,
        duration_seconds=result.duration_seconds,
    )
