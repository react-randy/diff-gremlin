"""A complete scan receipt, independent of its presentation."""

from dataclasses import dataclass

from diff_gremlin.domain.assessment import Assessment
from diff_gremlin.domain.sources import SourceIdentity
from diff_gremlin.domain.stages import StageResult


@dataclass(frozen=True, slots=True)
class ScanReport:
    source: SourceIdentity
    profile: str
    languages: tuple[str, ...]
    stages: list[StageResult]
    assessment: Assessment
    duration_seconds: float
    omitted_stages: tuple[str, ...] = ()
