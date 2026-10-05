"""Run the verified standalone PHPStan PHAR against a source-only snapshot."""

import tempfile
from functools import partial
from pathlib import Path

from diff_gremlin.analyzers.javascript.installed import trusted_executable
from diff_gremlin.analyzers.php.type_identity import LEVEL, VERSION
from diff_gremlin.analyzers.php.type_output import debug_document, diagnostics
from diff_gremlin.analyzers.php.type_workspace import (
    configuration,
    isolated_phar,
    source_view,
)
from diff_gremlin.analyzers.status import execution_status, unavailable
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult

MAX_OUTPUT = 64 * 1024 * 1024


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
            result = ctx.run(
                [
                    php,
                    "-n",
                    str(tool),
                    "analyse",
                    "--configuration",
                    str(config),
                    "--no-progress",
                    "--error-format=json",
                    "--memory-limit=512M",
                    "--debug",
                ],
                cwd=workspace,
                output_limit=MAX_OUTPUT,
                data_output=True,
            )
            status = execution_status(result, (0, 1))
            if status or result.returncode is None:
                return absent(
                    f"Controlled PHPStan invocation {result.status}; exit {result.returncode}",
                    status=status or "failed",
                )
            # Debug prints file names before JSON; remove no arbitrary text. Native
            # debug mode avoids worker subprocesses that could lose hardened -n.
            output = debug_document(result.stdout, locations)
            findings, unresolved = diagnostics(output, locations, result.returncode)
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
