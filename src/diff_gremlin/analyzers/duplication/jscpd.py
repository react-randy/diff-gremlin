"""Collect native clone evidence for an explicit scanner-owned language slice."""

import json
import tempfile
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from uuid import uuid4

from diff_gremlin.analyzers.duplication.locations import _clones
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
    valid_run,
)
from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult


@dataclass(frozen=True, slots=True)
class CloneLanguage:
    """Stage identity and native grammars supplied only by shipped adapters."""

    stage_id: str
    label: str
    languages: frozenset[str]
    formats: tuple[str, ...]


JAVASCRIPT = CloneLanguage(
    "javascript.duplication.jscpd",
    "JavaScript/TypeScript duplication",
    frozenset({"javascript", "typescript"}),
    ("javascript", "typescript", "jsx", "tsx"),
)
PHP = CloneLanguage(
    "php.duplication.jscpd",
    "PHP duplication",
    frozenset({"php"}),
    ("php",),
)
_LIMITS = {"minLines": 5, "minTokens": 50, "maxLines": 1000, "maxSize": "100kb"}
_MAX_REPORT_BYTES = 4 * 1024 * 1024


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


def _report_data(
    report_path: Path, expected: set[str], invocation: str, formats: tuple[str, ...]
):
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
    if data.get("requested_formats") != list(formats):
        raise ValueError("duplication native grammars differ from invocation")
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


def _report(
    report_path: Path, paths: dict[str, str], invocation: str, formats: tuple[str, ...]
):
    statistics, rows, detector, catalog = _report_data(
        report_path, set(paths), invocation, formats
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


def _observe(ctx, files, node, dependencies, language):
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
            json.dumps(
                {
                    "files": list(paths),
                    "invocation": invocation,
                    "formats": language.formats,
                }
            ),
            encoding="utf-8",
        )
        output = workspace / "output"
        result = ctx.run(
            [
                node,
                str(
                    Path(__file__).parents[1]
                    / "javascript"
                    / "assets"
                    / "duplication.cjs"
                ),
                *(str(package) for package in dependencies),
                str(config),
                "--output",
                str(output),
            ],
            cwd=workspace,
        )
        observations = (
            _report(output / "jscpd-report.json", paths, invocation, language.formats)
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


def analyze_duplication(ctx: ScanContext, language: CloneLanguage) -> StageResult:
    files = tuple(
        file for file in ctx.production_files if file.language in language.languages
    )

    absent = partial(
        unavailable,
        language.stage_id,
        language.label,
        "duplication",
        "jscpd",
        eligible_files=len(files),
    )

    if not files:
        return absent("No eligible production files", status="skipped")
    environment = _environment(ctx)
    if environment is None:
        return absent("Installed trusted Node/jscpd package unavailable")
    package, node, dependencies = environment
    try:
        result, observations = _observe(ctx, files, node, dependencies, language)
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
        language.stage_id,
        language.label,
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
