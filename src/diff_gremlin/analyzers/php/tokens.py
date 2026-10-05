"""Collect PHP parser evidence with bounded trusted helper invocations."""

import base64
import json
import shutil
import time
import uuid
from pathlib import Path

from diff_gremlin.analyzers.php.token_model import PHPTokenBatch
from diff_gremlin.analyzers.php.token_schema import parse_token_output
from diff_gremlin.analyzers.status import execution_status
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.process import trusted_path

_MAX_SOURCE = 8 * 1024 * 1024
_MAX_OUTPUT = 64 * 1024 * 1024


def php_executable(ctx: ScanContext) -> str | None:
    candidate = shutil.which("php", path=trusted_path(ctx.root))
    if candidate:
        resolved = Path(candidate).resolve()
        if not resolved.is_relative_to(ctx.root.resolve()):
            return str(resolved)
    return None


def _source(ctx: ScanContext, file: SourceFile) -> bytes:
    relative = Path(file.relative_path)
    resolved = file.path.resolve(strict=True)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or file.path.is_symlink()
        or not resolved.is_relative_to(ctx.root.resolve())
        or (ctx.root / relative).resolve() != resolved
        or not resolved.is_file()
        or resolved.stat().st_size > _MAX_SOURCE
    ):
        raise ValueError("source outside regular bounded inventory")
    source = resolved.read_bytes()
    if len(source) > _MAX_SOURCE:
        raise ValueError("source exceeds byte budget")
    return source


def collect_php_tokens(
    ctx: ScanContext, files: tuple[SourceFile, ...]
) -> PHPTokenBatch:
    batch = PHPTokenBatch()
    php = php_executable(ctx)
    if not php:
        batch.reasons.append("Trusted PHP parser unavailable")
        batch.failures.append("missing")
        return batch
    helper = Path(__file__).parent / "assets" / "tokens.php"
    deadline = time.monotonic() + ctx.timeout
    for file in files:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            batch.reasons.append("PHP parser cumulative time budget exhausted")
            batch.failures.append("timeout")
            break
        try:
            source = _source(ctx, file)
        except (OSError, ValueError, RuntimeError):
            batch.reasons.append("PHP source unavailable or outside byte/path budget")
            batch.failures.append("limited")
            continue
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            batch.reasons.append("PHP parser cumulative time budget exhausted")
            batch.failures.append("timeout")
            break
        nonce = uuid.uuid4().hex
        result = ctx.run(
            [php, "-n", str(helper)],
            cwd=ctx.scratch,
            timeout=remaining,
            output_limit=max(_MAX_OUTPUT, len(source) * 32),
            input_text=json.dumps(
                {"source": base64.b64encode(source).decode(), "nonce": nonce}
            ),
            data_output=True,
        )
        batch.duration += result.duration_seconds
        status = execution_status(result)
        if status:
            batch.failures.append(
                "limited" if result.status == "output_limit" else status
            )
            batch.reasons.append(
                f"PHP parser {result.status}; no complete evidence for a source file"
            )
            continue
        try:
            parsed, version = parse_token_output(result.stdout, source, file, nonce)
            if batch.version and batch.version != version:
                raise ValueError("runtime version changed")
        except (ValueError, TypeError, KeyError):
            batch.failures.append("failed")
            batch.reasons.append("PHP parser output failed source/schema validation")
            continue
        batch.version = version
        batch.files.append(parsed)
    return batch
