"""Report parser-backed contextual PHP security observations."""

import time

from diff_gremlin.analyzers.php.security_rules import observe_php_tokens
from diff_gremlin.analyzers.php.token_model import PHPFileTokens
from diff_gremlin.analyzers.php.tokens import collect_php_tokens
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_LIMIT = "Contextual token observations with approximate lexical request aliases; no whole-program dataflow, reachability or exploitability inference"


def _observe_files(
    files: list[PHPFileTokens], deadline: float, reasons: list[str]
) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    completed = 0
    for file in files:
        try:
            findings.extend(observe_php_tokens(file, deadline=deadline))
        except TimeoutError:
            reasons.append("PHP security token time budget exhausted")
            break
        completed += 1
    return findings, completed


def analyze_php_security(ctx: ScanContext) -> StageResult:
    files = tuple(file for file in ctx.files if file.language == "php")
    if not files:
        return StageResult(
            "security.php",
            "PHP security observations",
            "security",
            "unsupported",
            "php",
            reason="No PHP files",
            scope="current-php",
        )
    deadline = time.monotonic() + ctx.timeout
    batch = collect_php_tokens(ctx, files)
    parsed = [file for file in batch.files if not file.parse_error_line]
    reasons = list(batch.reasons)
    findings, completed = _observe_files(parsed, deadline, reasons)
    if len(parsed) != len(batch.files):
        reasons.append(
            "PHP syntax errors prevent security token observations for affected files"
        )
    return StageResult(
        "security.php",
        "PHP security observations",
        "security",
        "limited" if reasons and batch.files else batch.status,
        "php",
        version=batch.version,
        metrics={"call_count": len(findings), "actionable_count": len(findings)}
        if completed
        else {},
        findings=findings,
        reason="; ".join([*dict.fromkeys(reasons), _LIMIT]),
        scope="current-php",
        analyzed_files=completed,
        eligible_files=len(files),
        duration_seconds=batch.duration,
    )
