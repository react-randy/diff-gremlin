"""Immutable, source-validated PHP token evidence."""

from dataclasses import dataclass, field

from diff_gremlin.domain.context import SourceFile
from diff_gremlin.domain.stages import StageStatus


@dataclass(frozen=True, slots=True)
class PHPToken:
    kind: str
    text: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class PHPFileTokens:
    source: SourceFile
    tokens: tuple[PHPToken, ...]
    parse_error_line: int = 0


@dataclass(slots=True)
class PHPTokenBatch:
    files: list[PHPFileTokens] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    failures: list[StageStatus] = field(default_factory=list)
    version: str = ""
    duration: float = 0.0

    @property
    def status(self) -> StageStatus:
        if not self.reasons:
            return "ok"
        if self.files:
            return "limited"
        return self.failures[0] if self.failures else "failed"
