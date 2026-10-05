"""Collect PHP parser evidence with bounded trusted helper invocations."""

import shutil
import time
import uuid
from pathlib import Path

from diff_gremlin.analyzers.php.token_model import PHPTokenBatch
from diff_gremlin.analyzers.php.token_schema import parse_token_output
from diff_gremlin.analyzers.php.token_source import read_source as _source
from diff_gremlin.analyzers.php.token_transport import run_parser
from diff_gremlin.analyzers.status import execution_status
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult
from diff_gremlin.process import trusted_path


def php_executable(ctx: ScanContext) -> str | None:
    candidate = shutil.which("php", path=trusted_path(ctx.root))
    if candidate:
        resolved = Path(candidate).resolve()
        if not resolved.is_relative_to(ctx.root.resolve()):
            return str(resolved)
    return None


def _remaining(batch: PHPTokenBatch, deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        batch.reasons.append("PHP parser cumulative time budget exhausted")
        batch.failures.append("timeout")
    return remaining


def _admit_output(
    batch: PHPTokenBatch, result: RunResult, source: bytes, file: SourceFile, nonce: str
) -> None:
    try:
        parsed, version = parse_token_output(result.stdout, source, file, nonce)
        if batch.version and batch.version != version:
            raise ValueError("runtime version changed")
    except (ValueError, TypeError, KeyError):
        batch.failures.append("failed")
        batch.reasons.append("PHP parser output failed source/schema validation")
        return
    batch.version = version
    batch.files.append(parsed)


def _record_result(
    batch: PHPTokenBatch, result: RunResult, source: bytes, file: SourceFile, nonce: str
) -> None:
    batch.duration += result.duration_seconds
    status = execution_status(result)
    if status:
        batch.failures.append("limited" if result.status == "output_limit" else status)
        batch.reasons.append(
            f"PHP parser {result.status}; no complete evidence for a source file"
        )
        return
    _admit_output(batch, result, source, file, nonce)


def collect_php_tokens(
    ctx: ScanContext, files: tuple[SourceFile, ...]
) -> PHPTokenBatch:
    batch = PHPTokenBatch()
    php = php_executable(ctx)
    if not php:
        batch.reasons.append("Trusted PHP parser unavailable")
        batch.failures.append("missing")
        return batch
    deadline = time.monotonic() + ctx.timeout
    for file in files:
        remaining = _remaining(batch, deadline)
        if remaining <= 0:
            break
        try:
            source = _source(ctx, file)
        except (OSError, ValueError, RuntimeError):
            batch.reasons.append("PHP source unavailable or outside byte/path budget")
            batch.failures.append("limited")
            continue
        remaining = _remaining(batch, deadline)
        if remaining <= 0:
            break
        nonce = uuid.uuid4().hex
        result = run_parser(ctx, php, source, nonce, remaining)
        _record_result(batch, result, source, file, nonce)
    return batch
