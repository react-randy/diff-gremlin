"""PHP clone evidence under the shared native engine."""

from diff_gremlin.analyzers.duplication.jscpd import PHP, analyze_duplication
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult


def analyze_php_duplication(ctx: ScanContext) -> StageResult:
    return analyze_duplication(ctx, PHP)
