"""Compare stable identities while preserving both full evidence receipts."""

import hashlib
from collections import Counter
from dataclasses import asdict

from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.reporting.serialization import SCHEMA_VERSION, report_document


def identity(finding: Finding) -> str:
    if finding.fingerprint:
        return finding.fingerprint
    text = f"{finding.rule}\0{finding.path}\0{finding.symbol}\0{finding.message}"
    return hashlib.sha256(text.encode()).hexdigest()[:20]


def unmatched(findings: list[Finding], other: list[Finding]) -> list[dict]:
    remaining = Counter(identity(f) + ":" + f.severity for f in other)
    result = []
    for finding in findings:
        key = identity(finding) + ":" + finding.severity
        if remaining[key]:
            remaining[key] -= 1
        else:
            result.append(asdict(finding))
    return result


def numeric_deltas(base: StageResult, head: StageResult) -> dict:
    result = {}
    for key in base.metrics.keys() & head.metrics.keys():
        before, after = base.metrics[key], head.metrics[key]
        if type(before) in (int, float) and type(after) in (int, float):
            result[key] = {
                "base": before,
                "head": after,
                "delta": round(after - before, 4),
            }
    return result


def stage_delta(base: StageResult | None, head: StageResult | None) -> dict:
    comparable = base is not None and head is not None and base.status == head.status == "ok"
    return {
        "id": (head or base).id,
        "base_status": base.status if base else "absent",
        "head_status": head.status if head else "absent",
        "comparable": comparable,
        "base_score": stage_score(base) if base else None,
        "head_score": stage_score(head) if head else None,
        "metrics": numeric_deltas(base, head) if comparable else {},
        "added_findings": unmatched(head.findings, base.findings if base else []) if head else [],
        "resolved_findings": unmatched(base.findings, head.findings) if comparable else [],
        "resolution_note": "Resolution requires complete observations on both sides."
        if not comparable
        else "",
    }


def compare_document(
    base: ScanReport, head: ScanReport, *, review=None, comparison_base_sha=""
) -> dict:
    before = {stage.id: stage for stage in base.stages}
    after = {stage.id: stage for stage in head.stages}
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "comparison",
        "review": asdict(review) if review is not None else None,
        "comparison_base_sha": comparison_base_sha or base.source.commit_sha,
        "comparison_semantics": "exact supplied base snapshot versus exact supplied head; not a simulated merge result",
        "base": report_document(base),
        "head": report_document(head),
        "deltas": [
            stage_delta(before.get(key), after.get(key))
            for key in sorted(before.keys() | after.keys())
        ],
    }
