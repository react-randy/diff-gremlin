"""Run only the installed pinned parser, with source on stdin."""

import re
import time
from dataclasses import dataclass, field

from diff_gremlin.analyzers.javascript.installed import trusted_executable
from diff_gremlin.analyzers.shell.dialect import dialect
from diff_gremlin.analyzers.shell.schema import MAX_JSON_BYTES, decode
from diff_gremlin.analyzers.shell.source import (
    MAX_FILES,
    MAX_TOTAL_SOURCE_BYTES,
    read_source,
)
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageStatus

VERSION = "3.14.1"
MAX_TOTAL_OUTPUT_BYTES = 16 * 1024 * 1024


@dataclass
class Budget:
    """One capability's cumulative parser deadline and byte allowances."""

    deadline: float
    source_remaining: int = MAX_TOTAL_SOURCE_BYTES
    output_remaining: int = MAX_TOTAL_OUTPUT_BYTES

    def remaining_time(self) -> float:
        """Give each process only what remains of the original scan deadline."""
        return max(0.0, self.deadline - time.monotonic())

    def omission_reason(self, file: SourceFile) -> str:
        """Stop before reading or invoking another file after cumulative exhaustion."""
        if self.remaining_time() <= 0:
            return "time budget exhausted"
        if file.size_bytes > self.source_remaining:
            return "source byte budget exhausted"
        if self.output_remaining <= 0:
            return "output byte budget exhausted"
        return ""


@dataclass
class Parsed:
    """Internal validated trees and safe per-file failure evidence."""

    trees: list[tuple[SourceFile, dict]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    status: StageStatus = "ok"
    version: str = ""
    duration: float = 0.0


def installed_parser(ctx: ScanContext, timeout: float | None = None) -> tuple[str, str]:
    """Require a trusted binary reporting the exact reviewed parser version."""
    binary = trusted_executable(ctx, "shfmt")
    if not binary:
        return "", "Shell parser shfmt unavailable"
    result = ctx.run(
        [binary, "--version"], cwd=ctx.scratch, output_limit=1024, timeout=timeout
    )
    if (
        result.status != "ok"
        or result.returncode != 0
        or result.stdout.strip() != f"v{VERSION}"
    ):
        return "", "Shell parser version unavailable or differs from pinned 3.14.1"
    return binary, ""


def syntax_finding(file: SourceFile, stderr: str, source: str) -> Finding:
    """Retain a valid diagnostic location without exposing parser error text."""
    match = re.match(r"^(\d{1,9}):(\d{1,9}):", stderr)
    line, column = map(int, match.groups()) if match else (0, 0)
    lines = source.splitlines()
    if not (
        1 <= line <= len(lines) and 1 <= column <= len(lines[line - 1].encode()) + 1
    ):
        line, column = 0, 0
    return Finding(
        "shell.syntax-error",
        "Shell syntax parsing failed",
        "medium",
        file.relative_path,
        line,
        column,
    )


def parse_file(
    ctx: ScanContext, binary: str, file: SourceFile, parsed: Parsed, budget: Budget
) -> None:
    """Accumulate a validated file or a safe explicit incomplete reason."""
    try:
        source = read_source(ctx, file)
        language = dialect(source)
    except (OSError, UnicodeError, ValueError):
        parsed.reasons.append(
            f"Shell read, size or dialect unavailable: {file.relative_path}"
        )
        return
    if budget.remaining_time() <= 0:
        parsed.reasons.append(
            f"Shell cumulative time budget exhausted; omitted eligible file: {file.relative_path}"
        )
        return
    output_limit = min(MAX_JSON_BYTES, budget.output_remaining)
    result = ctx.run(
        [binary, "--to-json", f"-ln={language}"],
        cwd=ctx.scratch,
        input_text=source,
        data_output=True,
        output_limit=output_limit,
        timeout=budget.remaining_time(),
    )
    output_bytes = len(result.stdout.encode("utf-8")) + len(
        result.stderr.encode("utf-8")
    )
    budget.output_remaining -= (
        output_limit if result.status == "output_limit" else output_bytes
    )
    if output_bytes > output_limit:
        parsed.reasons.append(
            f"Shell parser output byte limit exceeded: {file.relative_path}"
        )
        return
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
    started = time.monotonic()
    budget = Budget(
        started + max(0.0, ctx.timeout), MAX_TOTAL_SOURCE_BYTES, MAX_TOTAL_OUTPUT_BYTES
    )
    if not files:
        parsed.status = "unsupported"
        parsed.reasons.append("No inventoried Shell files in this scope")
        return parsed
    if budget.remaining_time() <= 0:
        parsed.status = "limited"
        parsed.reasons.append(
            f"Shell cumulative time budget exhausted; omitted {len(files)} eligible files"
        )
        return parsed
    binary, reason = installed_parser(ctx, budget.remaining_time())
    if not binary:
        parsed.status = (
            "missing" if reason == "Shell parser shfmt unavailable" else "failed"
        )
        parsed.reasons.append(reason)
        if budget.remaining_time() <= 0:
            parsed.status = "timeout"
            parsed.reasons.append(
                f"Shell cumulative time budget exhausted during version probe; omitted {len(files)} eligible files"
            )
        parsed.duration = time.monotonic() - started
        return parsed
    parsed.version = VERSION
    parse_selected(ctx, binary, files, parsed, budget)
    if parsed.reasons:
        parsed.status = "limited"
    parsed.duration = time.monotonic() - started
    return parsed


def parse_selected(
    ctx: ScanContext,
    binary: str,
    files: tuple[SourceFile, ...],
    parsed: Parsed,
    budget: Budget,
) -> None:
    """Keep all omitted files eligible while retaining earlier validated trees."""
    for index, file in enumerate(files[:MAX_FILES]):
        if reason := budget.omission_reason(file):
            parsed.reasons.append(
                f"Shell cumulative {reason}; omitted {len(files) - index} eligible files"
            )
            return
        budget.source_remaining -= file.size_bytes
        parse_file(ctx, binary, file, parsed, budget)
    if len(files) > MAX_FILES:
        parsed.reasons.append(
            f"Shell file limit {MAX_FILES}; omitted {len(files) - MAX_FILES} eligible files"
        )
