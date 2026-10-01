"""Evidence produced by a single analysis capability."""

from dataclasses import dataclass, field
from typing import Literal

from diff_gremlin.domain.findings import Finding

StageStatus = Literal[
    "ok", "limited", "missing", "failed", "timeout", "unsupported", "skipped"
]
Category = Literal[
    "lint",
    "types",
    "complexity",
    "duplication",
    "security",
    "hygiene",
    "health",
    "maintainability",
    "history",
    "structure",
]


@dataclass(slots=True)
class StageResult:
    """Only validated observations may use status 'ok'."""

    id: str
    label: str
    category: Category
    status: StageStatus
    tool: str
    version: str = ""
    metrics: dict[str, object] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    reason: str = ""
    scope: str = "production"
    required: bool = True
    analyzed_files: int = 0
    eligible_files: int = 0
    duration_seconds: float = 0.0
