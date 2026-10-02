"""Own one analysis context and assemble its complete evidence receipt."""

import tempfile
import time
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


def scan(
    snapshot: Snapshot, *, profile: str = "full", timeout: float = 120.0
) -> ScanReport:
    from diff_gremlin.inventory import collect_inventory
    from diff_gremlin.process import run

    started = time.monotonic()
    inventory = collect_inventory(snapshot.root, snapshot.scope_manifest)
    selected = capabilities(inventory.languages)
    stages = [inventory.stage]
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
                stages.extend(invoke(capability, context))
        if profile == "full":
            stages.append(history_stage(snapshot, context))
    return ScanReport(
        snapshot.identity,
        profile,
        inventory.languages,
        stages,
        assess(stages),
        time.monotonic() - started,
        omitted_ids(selected, profile),
    )
