"""Detect limited current-tree credential patterns without exposing values."""

import json
import math
import re
import tempfile
from collections import Counter
from pathlib import Path

from diff_gremlin.analyzers.javascript.installed import trusted_executable
from diff_gremlin.analyzers.javascript.output import failure_status, positive, valid_run
from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_PROVIDER_RULES = (
    (
        "secret.github-token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b"),
    ),
    ("secret.gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b")),
    ("secret.aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("secret.slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("secret.google-api-key", re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b")),
    ("secret.stripe-key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
    ("secret.npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    (
        "secret.private-key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
)
_ASSIGNMENT = re.compile(
    r"""(?i)["']?\b(?:api[_-]?key|client[_-]?secret|secret|password|passwd|token|access[_-]?key)["']?\s*[:=]\s*["']?([^\s"',;#}\]]+)"""
)
_PLACEHOLDER = re.compile(
    r"(?i)(?:example|placeholder|changeme|dummy|your[_-]|replace[_-]|test[_-]|redacted|not[_-]a[_-]|xxxx|\$\{|getenv|environ|process\.env)"
)


def _candidate(value: str) -> bool:
    if len(value) < 12 or _PLACEHOLDER.search(value) or len(set(value)) < 6:
        return False
    entropy = -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in Counter(value).values()
    )
    return entropy >= 3.0


def _matches(text: str) -> list[tuple[str, int]]:
    matches = [
        (rule, match.start())
        for rule, pattern in _PROVIDER_RULES
        for match in pattern.finditer(text)
    ]
    for match in _ASSIGNMENT.finditer(text):
        if _candidate(match.group(1)):
            matches.append(("secret.credential-assignment", match.start()))
    return sorted(set(matches), key=lambda row: row[1])


def _analyze_patterns(ctx: ScanContext) -> StageResult:
    findings, skipped = [], []
    analyzed = 0
    for file in ctx.files:
        if file.size_bytes > 1024 * 1024:
            skipped.append(file.relative_path)
            continue
        try:
            text = file.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            skipped.append(file.relative_path)
            continue
        if "\x00" in text:
            skipped.append(file.relative_path)
            continue
        analyzed += 1
        for rule, offset in _matches(text):
            line = text.count("\n", 0, offset) + 1
            column = offset - text.rfind("\n", 0, offset)
            findings.append(
                Finding(
                    rule,
                    "Potential credential pattern; review locally and rotate if confirmed",
                    "high",
                    file.relative_path,
                    line,
                    column,
                    confidence="medium",
                )
            )
    return StageResult(
        "security.secrets",
        "Potential credential patterns",
        "security",
        "limited",
        "builtin-patterns",
        metrics={
            "match_count": len(findings),
            "skipped_paths": skipped,
            "history_scanned": False,
        },
        findings=findings,
        reason="Limited provider/private-key/assignment heuristics in current UTF-8 text; no match does not establish absence of secrets"
        + ("; unreadable/binary/large files omitted" if skipped else ""),
        scope="current-inventoried-text",
        analyzed_files=analyzed,
        eligible_files=len(ctx.files),
    )


def _gitleaks_row(row, source, selected):
    if (
        not isinstance(row, dict)
        or not isinstance(row.get("RuleID"), str)
        or not row["RuleID"]
    ):
        raise ValueError("invalid Gitleaks rule")
    path = row.get("File")
    if not isinstance(path, str):
        raise TypeError("invalid Gitleaks path")
    candidate = Path(path)
    candidate = candidate if candidate.is_absolute() else source / candidate
    relative = str(candidate.resolve().relative_to(source.resolve()))
    if (
        relative not in selected
        or not positive(row.get("StartLine"))
        or not positive(row.get("StartColumn"))
    ):
        raise ValueError("Gitleaks location outside copied inventory")
    # Secret, Match, Description, Fingerprint, and raw report rows never escape here.
    return Finding(
        "secret." + row["RuleID"],
        "Potential credential detector match; review locally and rotate if confirmed",
        "high",
        relative,
        row["StartLine"],
        row["StartColumn"],
        confidence="medium",
    )


def _gitleaks_findings(report: Path, source: Path, selected: set[str]) -> list[Finding]:
    rows = json.loads(report.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        raise TypeError("Gitleaks report must be a list")
    return [_gitleaks_row(row, source, selected) for row in rows]


def _copy_text(file, source):
    if file.size_bytes > 1024 * 1024:
        return False
    text = file.path.read_text(encoding="utf-8")
    if "\x00" in text:
        return False
    destination = source / file.relative_path
    if not destination.resolve().is_relative_to(source.resolve()):
        raise ValueError("inventory path escapes source view")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")
    return True


def _source_view(files, source):
    source.mkdir()
    selected, skipped = set(), []
    for file in files:
        try:
            if _copy_text(file, source):
                selected.add(file.relative_path)
            else:
                skipped.append(file.relative_path)
        except (OSError, UnicodeError, ValueError):
            skipped.append(file.relative_path)
    return selected, skipped


def _invoke_gitleaks(ctx, binary, source, workspace, report):
    config = Path(__file__).parent / "assets" / "gitleaks-v8.30.1.toml"
    ignore = workspace / "empty-ignore"
    ignore.write_text("", encoding="utf-8")
    return ctx.run(
        [
            binary,
            "dir",
            str(source),
            "--config",
            str(config),
            "--gitleaks-ignore-path",
            str(ignore),
            "--ignore-gitleaks-allow",
            "--redact=100",
            "--report-format",
            "json",
            "--report-path",
            str(report),
            "--no-banner",
            "--no-color",
            "--log-level",
            "error",
            "--max-decode-depth",
            "0",
            "--max-archive-depth",
            "0",
            "--max-target-megabytes",
            "1",
        ],
        cwd=workspace,
    )


def _report_findings(result, report, source, selected):
    findings = _gitleaks_findings(report, source, selected)
    if (result.returncode == 0 and findings) or (
        result.returncode == 1 and not findings
    ):
        raise ValueError("Gitleaks exit/report evidence inconsistent")
    return findings


def analyze_secrets(ctx: ScanContext) -> StageResult:
    """Use an installed, fixture-validated detector; preserve limited fallback."""
    binary = trusted_executable(ctx, "gitleaks")
    if not binary:
        return _analyze_patterns(ctx)
    with tempfile.TemporaryDirectory(prefix="gitleaks-", dir=ctx.scratch) as directory:
        workspace = Path(directory)
        source = workspace / "source"
        selected, skipped = _source_view(ctx.files, source)
        report = workspace / "report.json"
        result = _invoke_gitleaks(ctx, binary, source, workspace, report)
        if not valid_run(result, (0, 1)):
            return unavailable(
                "security.secrets",
                "Potential credential detector matches",
                "security",
                "gitleaks",
                f"Controlled Gitleaks invocation {result.status}; exit {result.returncode}",
                status=failure_status(result),
                eligible_files=len(ctx.files),
            )
        try:
            findings = _report_findings(result, report, source, selected)
        except (OSError, ValueError, TypeError):
            return unavailable(
                "security.secrets",
                "Potential credential detector matches",
                "security",
                "gitleaks",
                "Fresh Gitleaks JSON missing, malformed, or inconsistent with exit/selected inventory",
                status="failed",
                eligible_files=len(ctx.files),
            )
    return StageResult(
        "security.secrets",
        "Potential credential detector matches",
        "security",
        "limited" if skipped else "ok",
        "gitleaks",
        tool_version(ctx, binary),
        metrics={
            "match_count": len(findings),
            "skipped_paths": skipped,
            "history_scanned": False,
        },
        findings=findings,
        reason="Controlled upstream v8.30.1 rules with global filename exclusions removed, target suppressions disabled; no match does not establish absence of secrets; archives/decoding/history excluded"
        + ("; unreadable/binary/large files omitted" if skipped else ""),
        scope="current-inventoried-text",
        analyzed_files=len(selected),
        eligible_files=len(ctx.files),
        duration_seconds=result.duration_seconds,
    )
