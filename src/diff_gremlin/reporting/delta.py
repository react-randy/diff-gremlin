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
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:20]


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
        if (
            isinstance(before, (int, float))
            and isinstance(after, (int, float))
            and not isinstance(before, bool)
            and not isinstance(after, bool)
        ):
            result[key] = {
                "base": before,
                "head": after,
                "delta": round(after - before, 4),
            }
    return result


def side_details(stage: StageResult | None) -> dict:
    if stage is None:
        return {"status": "absent", "score": None, "findings": []}
    return {
        "status": stage.status,
        "score": stage_score(stage),
        "findings": stage.findings,
    }


def confirmed_changes(base: StageResult | None, head: StageResult | None) -> dict:
    if base is None or head is None or base.status != "ok" or head.status != "ok":
        return {
            "comparable": False,
            "metrics": {},
            "resolved_findings": [],
            "resolution_note": "Resolution requires complete observations on both sides.",
        }
    return {
        "comparable": True,
        "metrics": numeric_deltas(base, head),
        "resolved_findings": unmatched(base.findings, head.findings),
        "resolution_note": "",
    }


def stage_delta(base: StageResult | None, head: StageResult | None) -> dict:
    stage = head or base
    if stage is None:
        raise ValueError("A delta requires at least one observed stage")
    before, after = side_details(base), side_details(head)
    return {
        "id": stage.id,
        "base_status": before["status"],
        "head_status": after["status"],
        "base_score": before["score"],
        "head_score": after["score"],
        "added_findings": unmatched(after["findings"], before["findings"]),
        **confirmed_changes(base, head),
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
