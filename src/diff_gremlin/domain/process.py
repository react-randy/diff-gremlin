"""The contract for a bounded child process."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol


@dataclass(frozen=True, slots=True)
class RunResult:
    """Completed execution is separate from adapter-specific exit semantics."""

    args: tuple[str, ...]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    status: Literal["ok", "missing", "timeout", "failed", "output_limit"] = "ok"
    duration_seconds: float = 0.0


class Runner(Protocol):
    """Run installed tools; callers never request a shell."""

    def __call__(
        self,
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float = 120.0,
        env: Mapping[str, str] | None = None,
        output_limit: int = 4 * 1024 * 1024,
        input_text: str | None = None,
    ) -> RunResult: ...
