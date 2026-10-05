"""Run the verified standalone PHPStan PHAR against a source-only snapshot."""

import tempfile
from functools import partial
from pathlib import Path

from diff_gremlin.analyzers.javascript.installed import trusted_executable
from diff_gremlin.analyzers.php.type_identity import LEVEL, VERSION
from diff_gremlin.analyzers.php.type_runtime import TypeInvocationError, native_evidence
from diff_gremlin.analyzers.php.type_workspace import (
    configuration,
    isolated_phar,
    source_view,
)
from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult


def analyze_php_types(ctx: ScanContext) -> StageResult:
    """No Composer, framework plugin, target configuration or PHP execution is used."""
    files = tuple(f for f in ctx.production_files if f.language == "php")
    absent = partial(
        unavailable,
        "php.types.phpstan",
        "PHP snapshot types",
        "types",
        "phpstan",
        eligible_files=len(files),
    )
    if not files:
        return absent("No production PHP files", status="skipped", required=False)
    php, phar = trusted_executable(ctx, "php"), trusted_executable(ctx, "phpstan.phar")
    if php is None or phar is None:
        return absent(
            "Trusted PHP CLI and reviewed standalone phpstan.phar are required; run doctor"
        )
    try:
        with tempfile.TemporaryDirectory(
            prefix="phpstan-", dir=ctx.scratch
        ) as directory:
            workspace = Path(directory)
            tool = isolated_phar(Path(phar), workspace)
            locations = source_view(files, workspace)
            config = configuration(workspace, tuple(locations))
            result, findings, unresolved = native_evidence(
                ctx, php, tool, config, workspace, locations
            )
    except TypeInvocationError as error:
        return absent(str(error), status=error.status)
    except (OSError, ValueError, TypeError) as error:
        return absent(f"PHPStan evidence rejected: {error}", status="failed")
    return StageResult(
        "php.types.phpstan",
        "PHP snapshot types",
        "types",
        "limited" if unresolved else "ok",
        "phpstan",
        VERSION,
        metrics={
            "error_count": len(findings) - unresolved,
            "warning_count": unresolved,
            "unresolved_symbols": unresolved,
            "level": LEVEL,
            "dependency_resolution": "source-only-static-reflection-no-vendor",
            "target_execution": False,
        },
        findings=findings,
        reason=(
            "Snapshot symbols are unresolved; framework/vendor dependencies are not installed"
            if unresolved
            else "Reduced snapshot level 5; no vendor, framework extensions or application bootstrap"
        ),
        scope="production-php-source-snapshot",
        analyzed_files=len(files),
        eligible_files=len(files),
        duration_seconds=result.duration_seconds,
    )
