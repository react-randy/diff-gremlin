"""Public bounded installed-tool execution interface."""

from collections.abc import Mapping, Sequence
from pathlib import Path

from diff_gremlin.domain.process import RunResult
from diff_gremlin.runtime.environment import minimal_environment, redact, trusted_path
from diff_gremlin.runtime.launch import execute as _execute


def run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float = 120.0,
    env: Mapping[str, str] | None = None,
    output_limit: int = 4194304,
    input_text: str | None = None,
    data_output: bool = False,
) -> RunResult:
    """Run a trusted installed executable without a shell or target configuration."""
    return _execute(
        command,
        cwd=cwd,
        timeout=timeout,
        env=env,
        output_limit=output_limit,
        input_text=input_text,
        protect_stdout=not data_output,
    )


__all__ = ["minimal_environment", "redact", "trusted_path"]
