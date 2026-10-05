"""Keep unsupported Blade templates visible as source coverage gaps."""

from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult


def analyze_blade_scope(ctx: ScanContext) -> StageResult:
    files = tuple(file for file in ctx.files if file.language == "php-blade")
    return StageResult(
        "php.templates.blade",
        "Blade template coverage",
        "structure",
        "unsupported",
        "scope",
        metrics={"unsupported_paths": [file.relative_path for file in files]},
        reason="Blade templates are outside PHP syntax/type/complexity/clone/security scope; inventoried Unicode and secret checks still apply",
        scope="current-blade-templates",
        eligible_files=len(files),
    )
