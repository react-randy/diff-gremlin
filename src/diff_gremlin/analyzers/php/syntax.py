"""Report located PHP syntax diagnostics from native parser tokens."""

from diff_gremlin.analyzers.php.tokens import collect_php_tokens
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult


def analyze_php_syntax(ctx: ScanContext) -> StageResult:
    files = tuple(file for file in ctx.files if file.language == "php")
    if not files:
        return StageResult(
            "php.syntax.php",
            "PHP syntax",
            "structure",
            "unsupported",
            "php",
            reason="No PHP files",
            scope="current-php",
        )
    batch = collect_php_tokens(ctx, files)
    findings = [
        Finding(
            "php.syntax.parse-error",
            "PHP parser rejected source syntax",
            "medium",
            file.source.relative_path,
            file.parse_error_line,
            1,
        )
        for file in batch.files
        if file.parse_error_line
    ]
    return StageResult(
        "php.syntax.php",
        "PHP syntax",
        "structure",
        batch.status,
        "php",
        version=batch.version,
        metrics={"parse_error_count": len(findings)} if batch.files else {},
        findings=findings,
        reason="; ".join(dict.fromkeys(batch.reasons)),
        scope="current-php",
        analyzed_files=len(batch.files),
        eligible_files=len(files),
        duration_seconds=batch.duration,
    )
