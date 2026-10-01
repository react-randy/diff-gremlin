"""Inputs shared by installed static analyzers."""

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from diff_gremlin.domain.process import Runner, RunResult


@dataclass(frozen=True, slots=True)
class SourceFile:
    """One inventoried regular file in an owned snapshot."""

    path: Path
    relative_path: str
    language: str
    is_test: bool
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Analyzer inputs contain no provider credentials or executable config."""

    root: Path
    files: tuple[SourceFile, ...]
    production_files: tuple[SourceFile, ...]
    languages: tuple[str, ...]
    profile: str
    timeout: float
    scratch: Path
    runner: Runner

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
        output_limit: int = 4 * 1024 * 1024,
        input_text: str | None = None,
    ) -> RunResult:
        """Apply this scan's execution deadline to an installed tool."""
        return self.runner(
            command,
            cwd=cwd if cwd is not None else self.root,
            timeout=timeout if timeout is not None else self.timeout,
            output_limit=output_limit,
            input_text=input_text,
        )
