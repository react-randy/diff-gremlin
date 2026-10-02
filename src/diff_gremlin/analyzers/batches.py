"""Bound installed-tool batches and retain only independently validated evidence."""

import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from diff_gremlin.analyzers.status import execution_status
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult
from diff_gremlin.domain.stages import StageStatus

MAX_BATCH_FILES = 32
MAX_BATCH_SOURCE_BYTES = 512 * 1024
MAX_BATCH_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_FILE_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_TOTAL_OUTPUT_BYTES = 64 * 1024 * 1024


@dataclass
class BatchEvidence[T]:
    """Validated observations and exact file coverage under one deadline."""

    deadline: float
    values: list[T] = field(default_factory=list)
    analyzed: int = 0
    status: StageStatus = "ok"
    reason: str = ""
    output_bytes: int = 0

    def remaining_time(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def stop(self, status: StageStatus, reason: str) -> None:
        self.status = "limited" if self.analyzed else status
        self.reason = reason


def selected_batches(files: tuple[SourceFile, ...]):
    """Keep argument lists and likely output small without omitting large files."""
    batch = []
    size = 0
    for file in files:
        if batch and (
            len(batch) >= MAX_BATCH_FILES
            or size + file.size_bytes > MAX_BATCH_SOURCE_BYTES
        ):
            yield tuple(batch)
            batch, size = [], 0
        batch.append(file)
        size += file.size_bytes
    if batch:
        yield tuple(batch)


def output_allowance(batch: tuple[SourceFile, ...], used: int) -> int:
    """Scale a single-file allowance within the fixed cumulative ceiling."""
    bound = MAX_BATCH_OUTPUT_BYTES
    if len(batch) == 1:
        bound = min(MAX_FILE_OUTPUT_BYTES, max(bound, batch[0].size_bytes * 128))
    return min(bound, MAX_TOTAL_OUTPUT_BYTES - used)


def capture_batch[T](
    ctx: ScanContext,
    batch: tuple[SourceFile, ...],
    command: Sequence[str],
    evidence: BatchEvidence[T],
    allowance: int,
) -> tuple[RunResult, bool]:
    """Capture one bounded output and account for every attempted byte."""
    result = ctx.run(
        [*command, "--", *(str(file.path) for file in batch)],
        cwd=ctx.scratch,
        timeout=evidence.remaining_time(),
        output_limit=allowance,
        data_output=True,
    )
    size = sum(
        len(text.encode("utf-8", "surrogateescape"))
        for text in (result.stdout, result.stderr)
    )
    overflow = result.status == "output_limit" or size > allowance
    evidence.output_bytes += allowance if overflow else size
    return result, overflow


def accept_batch[T](
    evidence: BatchEvidence[T],
    batch: tuple[SourceFile, ...],
    result: RunResult,
    validate: Callable[[tuple[SourceFile, ...], RunResult], list[T]],
) -> bool:
    """Publish coverage only after that exact batch's schema validates."""
    try:
        values = validate(batch, result)
    except (ValueError, TypeError):
        evidence.stop("failed", "output failed schema or coverage validation")
        return False
    evidence.values.extend(values)
    evidence.analyzed += len(batch)
    return True


def collect_batches[T](
    ctx: ScanContext,
    files: tuple[SourceFile, ...],
    command: Sequence[str],
    allowed_codes: tuple[int, ...],
    validate: Callable[[tuple[SourceFile, ...], RunResult], list[T]],
) -> BatchEvidence[T]:
    """Split overflowing batches, accounting for discarded output and elapsed time."""
    evidence: BatchEvidence[T] = BatchEvidence(time.monotonic() + ctx.timeout)
    pending = deque(selected_batches(files))
    while pending:
        if evidence.remaining_time() <= 0:
            evidence.stop("timeout", "cumulative time budget exhausted")
            break
        batch = pending.popleft()
        allowance = output_allowance(batch, evidence.output_bytes)
        if allowance <= 0:
            evidence.stop("failed", "cumulative output byte budget exhausted")
            break
        result, overflow = capture_batch(ctx, batch, command, evidence, allowance)
        if overflow and len(batch) > 1:
            middle = len(batch) // 2
            pending.appendleft(batch[middle:])
            pending.appendleft(batch[:middle])
            continue
        if overflow:
            evidence.stop("failed", "per-file output byte limit exceeded")
            break
        if status := execution_status(result, allowed_codes):
            evidence.stop(status, "execution did not complete valid analysis")
            break
        if not accept_batch(evidence, batch, result, validate):
            break
    if evidence.reason:
        evidence.reason += f"; omitted {len(files) - evidence.analyzed} eligible files"
    return evidence
