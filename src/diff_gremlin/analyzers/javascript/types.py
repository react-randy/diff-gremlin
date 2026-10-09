"""Collect bounded TypeScript diagnostics with fixed compiler options."""

from functools import partial
from pathlib import Path

from diff_gremlin.analyzers.javascript.installed import (
    installed_package,
    package_version,
    trusted_executable,
)
from diff_gremlin.analyzers.javascript.output import (
    evidence,
    failure_status,
    located_findings,
    natural,
    valid_run,
)
from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult

_ID, _LABEL = "typescript.types.tsc", "TypeScript static types"
_ENVIRONMENT_RULES = frozenset(
    {"TS2307", "TS2688", "TS2792", "TS7016", "TS6059", "TS6307", "TS7026", "TS2875"}
)


def _diagnostics(stdout, files):
    data = evidence(stdout, files)
    if not all(
        natural(data.get(k))
        for k in (
            "error_count",
            "warning_count",
            "dependency_count",
            "global_count",
        )
    ):
        raise ValueError("invalid diagnostic counts")
    findings = located_findings(
        data["findings"], files, kind="typescript", native_messages=True
    )
    if (
        len(findings) + data["global_count"]
        != data["error_count"] + data["warning_count"]
    ):
        raise ValueError("incomplete diagnostic counts")
    environment = [
        finding for finding in findings if finding.rule in _ENVIRONMENT_RULES
    ]
    source = [finding for finding in findings if finding.rule not in _ENVIRONMENT_RULES]
    data["environment_count"] = len(environment) + data["global_count"]
    data["environment_diagnostics"] = {
        rule: sum(finding.rule == rule for finding in environment)
        for rule in sorted({finding.rule for finding in environment})
    }
    data["environment_examples"] = {
        rule: next(finding.message for finding in environment if finding.rule == rule)
        for rule in data["environment_diagnostics"]
    }
    data["source_error_count"] = sum(finding.severity == "medium" for finding in source)
    data["source_warning_count"] = len(source) - data["source_error_count"]
    return data, source


def _type_environment(ctx):
    package = installed_package(ctx, "tsc", "typescript")
    node = trusted_executable(ctx, "node")
    return (node, package) if node and package else None


def _type_metrics(data):
    return {
        key: data[key]
        for key in (
            "error_count",
            "warning_count",
            "dependency_count",
            "global_count",
            "environment_count",
            "environment_diagnostics",
            "environment_examples",
            "source_error_count",
            "source_warning_count",
        )
    }


def _type_limit(data):
    return data["dependency_count"] > 0 or data["environment_count"] > 0


def _type_reason(data):
    if not _type_limit(data):
        return (
            "Fixed static options; project configuration and implicit imports excluded"
        )
    counts = ", ".join(
        f"{rule}: {count}" for rule, count in data["environment_diagnostics"].items()
    )
    if data["global_count"]:
        counts = ", ".join(filter(None, (counts, f"global: {data['global_count']}")))
    return f"Fixed static options; dependency/JSX environment diagnostics aggregated ({counts}); semantics remain limited"


def analyze_ts_types(ctx: ScanContext) -> StageResult:
    files = tuple(
        file for file in ctx.production_files if file.language == "typescript"
    )

    absent = partial(
        unavailable, _ID, _LABEL, "types", "tsc", eligible_files=len(files)
    )

    if not files:
        return absent("No TypeScript production files", status="skipped")
    environment = _type_environment(ctx)
    if environment is None:
        return absent("Installed trusted Node/TypeScript package unavailable")
    node, package = environment
    result = ctx.run(
        [
            node,
            str(Path(__file__).parent / "assets" / "types.cjs"),
            str(package),
            *(str(f.path.resolve()) for f in files),
        ],
        cwd=ctx.scratch,
    )
    if not valid_run(result):
        return absent(
            f"Controlled TypeScript invocation {result.status}; exit {result.returncode}",
            status=failure_status(result),
        )
    try:
        data, findings = _diagnostics(result.stdout, files)
    except (ValueError, TypeError) as error:
        return absent(
            f"Controlled TypeScript evidence invalid: {error}",
            status="failed",
        )
    limited = _type_limit(data)
    return StageResult(
        _ID,
        _LABEL,
        "types",
        "limited" if limited else "ok",
        "typescript",
        package_version(package),
        metrics=_type_metrics(data),
        findings=findings,
        reason=_type_reason(data),
        scope="standalone-static",
        eligible_files=len(files),
        analyzed_files=len(files),
        duration_seconds=result.duration_seconds,
    )
