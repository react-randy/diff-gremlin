"""Compare stable identities while preserving both full evidence receipts."""

from dataclasses import asdict

from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.comparison import delta_assessment
from diff_gremlin.policy.metrics import number, stage_score
from diff_gremlin.reporting.delta_matching import ChangedLines, match_findings
from diff_gremlin.reporting.serialization import SCHEMA_VERSION, report_document


def numeric_deltas(base: StageResult, head: StageResult) -> dict:
    result = {}
    for key in base.metrics.keys() & head.metrics.keys():
        before, after = number(base, key), number(head, key)
        if before is not None and after is not None:
            result[key] = {
                "base": base.metrics[key],
                "head": head.metrics[key],
                "delta": round(after - before, 4),
            }
    return result


def comparison_limit(base: StageResult | None, head: StageResult | None) -> str:
    if base is None or head is None or base.status != "ok" or head.status != "ok":
        return "Resolution requires complete observations on both sides."
    if base.tool != head.tool or base.version != head.version:
        return "Resolution requires observations from the same tool and version."
    if base.scope != head.scope or base.category != head.category:
        return (
            "Resolution requires observations of the same analysis scope and category."
        )
    return ""


def stage_delta(
    base: StageResult | None,
    head: StageResult | None,
    *,
    base_changed_lines: ChangedLines | None = None,
    head_changed_lines: ChangedLines | None = None,
    compatibility_note: str = "",
) -> dict:
    stage = head or base
    if stage is None:
        raise ValueError("A delta requires at least one observed stage")
    limit = compatibility_note or comparison_limit(base, head)
    changes = match_findings(
        base.findings if base else [],
        head.findings if head else [],
        base_lines=base_changed_lines,
        head_lines=head_changed_lines,
    )
    if limit:
        changes["resolved_findings"] = []
        changes["added_findings"].extend(
            item["head"] for item in changes["changed_findings"]
        )
        changes["changed_findings"] = []
    ambiguity_note = (
        "Duplicate identities with unmatched observations remain ambiguous; their resolutions are unconfirmed."
        if changes["ambiguous_identities"]
        else ""
    )
    body_note = (
        "Changed anonymous bodies remain unmatched; function continuity is unknown."
        if changes["uncertain_identities"]
        else ""
    )
    return {
        "id": stage.id,
        "base_status": base.status if base else "absent",
        "head_status": head.status if head else "absent",
        "base_reason": base.reason if base else "Stage not observed in base snapshot",
        "head_reason": head.reason if head else "Stage not observed in head snapshot",
        "base_score": stage_score(base) if base else None,
        "head_score": stage_score(head) if head else None,
        "comparable": not bool(limit),
        "metrics": numeric_deltas(base, head) if not limit and base and head else {},
        **changes,
        "resolution_note": " ".join(
            item for item in (limit, ambiguity_note, body_note) if item
        ),
    }


def compare_document(
    base: ScanReport,
    head: ScanReport,
    *,
    review=None,
    comparison_base_sha="",
    base_changed_lines: ChangedLines | None = None,
    head_changed_lines: ChangedLines | None = None,
) -> dict:
    before = {stage.id: stage for stage in base.stages}
    after = {stage.id: stage for stage in head.stages}
    deltas = [
        stage_delta(
            before.get(key),
            after.get(key),
            base_changed_lines=base_changed_lines,
            head_changed_lines=head_changed_lines,
            compatibility_note=(
                "Comparison requires the same analysis profile."
                if base.profile != head.profile
                else ""
            ),
        )
        for key in sorted(before.keys() | after.keys())
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "comparison",
        "review": asdict(review) if review is not None else None,
        "comparison_base_sha": comparison_base_sha or base.source.commit_sha,
        "comparison_semantics": "exact supplied base snapshot versus exact supplied head; not a simulated merge result",
        "base": report_document(base),
        "head": report_document(head),
        "deltas": deltas,
        "delta_assessment": delta_assessment(base, head, deltas),
    }
