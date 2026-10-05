"""Create redacted, located contextual PHP findings."""

from diff_gremlin.analyzers.php.token_model import PHPFileTokens, PHPToken
from diff_gremlin.domain.findings import Finding, Severity


def finding(
    file: PHPFileTokens, token: PHPToken, rule: str, message: str, severity: Severity
) -> Finding:
    return Finding(
        f"security.php.{rule}",
        message,
        severity,
        file.source.relative_path,
        token.line,
        token.column,
        confidence="medium",
    )
