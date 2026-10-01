"""Run only the installed pinned parser, with source on stdin."""

import re
from dataclasses import dataclass, field

from diff_gremlin.analyzers.javascript.installed import trusted_executable
from diff_gremlin.analyzers.shell.dialect import dialect
from diff_gremlin.analyzers.shell.schema import MAX_JSON_BYTES, decode
from diff_gremlin.analyzers.shell.source import MAX_FILES, read_source
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageStatus

VERSION = "3.14.1"


@dataclass
class Parsed:
    """Internal validated trees and safe per-file failure evidence."""

    trees: list[tuple[SourceFile, dict]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    status: StageStatus = "ok"
    version: str = ""
    duration: float = 0.0


def installed_parser(ctx: ScanContext) -> tuple[str, str]:
    """Require a trusted binary reporting the exact reviewed parser version."""
    binary = trusted_executable(ctx, "shfmt")
    if not binary:
        return "", "Shell parser shfmt unavailable"
    result = ctx.run([binary, "--version"], cwd=ctx.scratch, output_limit=1024)
    if result.status != "ok" or result.returncode != 0 or result.stdout.strip() != f"v{VERSION}":
        return "", "Shell parser version unavailable or differs from pinned 3.14.1"
    return binary, ""


def syntax_finding(file: SourceFile, stderr: str, source: str) -> Finding:
    """Retain a valid diagnostic location without exposing parser error text."""
    match = re.match(r"^(\d{1,9}):(\d{1,9}):", stderr)
    line, column = map(int, match.groups()) if match else (0, 0)
    lines = source.splitlines()
    if not (1 <= line <= len(lines) and 1 <= column <= len(lines[line - 1].encode()) + 1):
        line, column = 0, 0
    return Finding(
        "shell.syntax-error",
        "Shell syntax parsing failed",
        "medium",
        file.relative_path,
        line,
        column,
    )


def parse_file(ctx: ScanContext, binary: str, file: SourceFile, parsed: Parsed) -> None:
    """Accumulate a validated file or a safe explicit incomplete reason."""
    try:
        source = read_source(ctx, file)
        language = dialect(source)
    except (OSError, UnicodeError, ValueError):
        parsed.reasons.append(f"Shell read, size or dialect unavailable: {file.relative_path}")
        return
    result = ctx.run(
        [binary, "--to-json", f"-ln={language}"],
        cwd=ctx.scratch,
        input_text=source,
        data_output=True,
        output_limit=MAX_JSON_BYTES,
    )
    parsed.duration += result.duration_seconds
    if result.status != "ok" or result.returncode != 0:
        parsed.reasons.append(
            f"Shell parser {result.status}; exit {result.returncode}: {file.relative_path}"
        )
        if result.status == "ok":
            parsed.findings.append(syntax_finding(file, result.stderr, source))
        return
    try:
        parsed.trees.append((file, decode(result.stdout, source)))
    except (ValueError, TypeError, KeyError, RecursionError):
        parsed.reasons.append(
            f"Shell AST schema or resource validation failed: {file.relative_path}"
        )


def parse_files(ctx: ScanContext, files: tuple[SourceFile, ...]) -> Parsed:
    """Preserve coverage counts and partial evidence under every bounded failure."""
    parsed = Parsed()
    if not files:
        parsed.status = "unsupported"
        parsed.reasons.append("No inventoried Shell files in this scope")
        return parsed
    binary, reason = installed_parser(ctx)
    if not binary:
        parsed.status = "missing" if reason == "Shell parser shfmt unavailable" else "failed"
        parsed.reasons.append(reason)
        return parsed
    parsed.version = VERSION
    for file in files[:MAX_FILES]:
        parse_file(ctx, binary, file, parsed)
    if len(files) > MAX_FILES:
        parsed.reasons.append(
            f"Shell file limit {MAX_FILES}; omitted {len(files) - MAX_FILES} eligible files"
        )
    if parsed.reasons:
        parsed.status = "limited"
    return parsed
