"""Execute and validate controlled PHPStan native evidence."""

from pathlib import Path

from diff_gremlin.analyzers.php.type_output import debug_document, diagnostics
from diff_gremlin.analyzers.status import execution_status
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.process import RunResult
from diff_gremlin.domain.stages import StageStatus

MAX_OUTPUT = 64 * 1024 * 1024


class TypeInvocationError(ValueError):
    def __init__(self, message: str, status: StageStatus):
        super().__init__(message)
        self.status = status


def native_evidence(
    ctx: ScanContext,
    php: str,
    tool: Path,
    config: Path,
    workspace: Path,
    locations: dict[Path, SourceFile],
) -> tuple[RunResult, list[Finding], int]:
    """Require valid transport, exact per-file progress and located diagnostics."""
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
        raise TypeInvocationError(
            f"Controlled PHPStan invocation {result.status}; exit {result.returncode}",
            status or "failed",
        )
    # Debug prints file names before JSON; remove no arbitrary text. Native
    # debug mode avoids worker subprocesses that could lose hardened -n.
    output = debug_document(result.stdout, locations)
    findings, unresolved = diagnostics(output, locations, result.returncode)
    return result, findings, unresolved
