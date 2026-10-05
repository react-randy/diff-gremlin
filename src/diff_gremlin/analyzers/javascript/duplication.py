"""JavaScript/TypeScript clone evidence under the shared native engine."""

from diff_gremlin.analyzers.duplication.jscpd import JAVASCRIPT, analyze_duplication
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult


def analyze_js_duplication(ctx: ScanContext) -> StageResult:
    return analyze_duplication(ctx, JAVASCRIPT)
