"""Own one analysis context and assemble its complete evidence receipt."""

import tempfile
import time
from collections.abc import Callable
from pathlib import Path

from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.sources import Snapshot
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.orchestration.selection import Capability, capabilities, omitted_ids
from diff_gremlin.policy.assessment import assess


def invoke(capability: Capability, context: ScanContext) -> list[StageResult]:
    started = time.monotonic()
    try:
        observation = capability.analyze(context)
    except (OSError, ValueError, RuntimeError) as error:
        observation = StageResult(
            capability.id,
            capability.label,
            capability.category,
            "failed",
            "adapter",
            reason=f"Adapter failed during {capability.id}: {type(error).__name__}",
        )
    results = observation if isinstance(observation, list) else [observation]
    elapsed = time.monotonic() - started
    for result in results:
        result.duration_seconds = round(elapsed, 3)
    return results


def history_stage(snapshot: Snapshot, context: ScanContext) -> StageResult:
    """Only a captured repository can supply the snapshot's Git history."""
    from diff_gremlin.analyzers.history import analyze_history
    from diff_gremlin.analyzers.status import unavailable

    if getattr(snapshot, "selection", None) is not None:
        return unavailable(
            "history.git",
            "Python complexity history",
            "history",
            "git",
            required=False,
            reason="Repository history is outside this selected-path scan",
            status="unsupported",
        )
    if snapshot.history_repo is None:
        return unavailable(
            "history.git",
            "Python complexity history",
            "history",
            "git",
            required=False,
            reason="No Git history was captured for this source",
            status="unsupported",
        )
    return analyze_history(
        context,
        snapshot.history_repo,
        revision=snapshot.identity.commit_sha or None,
    )


def record_stages(
    stages: list[StageResult],
    results: list[StageResult],
    progress: Callable[[StageResult], None] | None,
) -> None:
    """Publish each completed observation before beginning the next capability."""
    stages.extend(results)
    if progress is not None:
        for result in results:
            progress(result)


def selection_stage(selection: dict | None) -> list[StageResult]:
    """Keep intentionally excluded repository paths distinct from analyzer gaps."""
    if selection is None:
        return []
    return [
        StageResult(
            "scope.selection",
            "Selected source paths",
            "structure",
            "limited",
            "builtin",
            metrics=selection,
            reason="Only selected paths were scanned; repository evidence is partial",
            scope="selected-paths",
        )
    ]


def scan(
    snapshot: Snapshot,
    *,
    profile: str = "full",
    timeout: float = 120.0,
    progress: Callable[[StageResult], None] | None = None,
) -> ScanReport:
    from diff_gremlin.inventory import collect_inventory
    from diff_gremlin.process import run

    started = time.monotonic()
    inventory = collect_inventory(snapshot.root, snapshot.scope_manifest)
    selected = capabilities(inventory.languages)
    stages = []
    selection = getattr(snapshot, "selection", None)
    record_stages(stages, [inventory.stage, *selection_stage(selection)], progress)
    with tempfile.TemporaryDirectory(prefix="diff-gremlin-analysis-") as directory:
        context = ScanContext(
            snapshot.root,
            inventory.files,
            inventory.production_files,
            inventory.languages,
            profile,
            timeout,
            Path(directory),
            run,
            inventory.scope_manifest,
        )
        for capability in selected:
            if profile == "full" or not capability.full_only:
                results = invoke(capability, context)
                record_stages(stages, results, progress)
        if profile == "full":
            history = history_stage(snapshot, context)
            record_stages(stages, [history], progress)
    return ScanReport(
        snapshot.identity,
        profile,
        inventory.languages,
        stages,
        assess(stages),
        time.monotonic() - started,
        omitted_ids(selected, profile),
        selection,
    )
