"""Concrete next actions without safety certificates."""

from diff_gremlin.domain.findings import SEVERITY_ORDER
from diff_gremlin.domain.reports import ScanReport


def missing_actions(report: ScanReport) -> list[str]:
    return [
        f"Complete {stage.id}: {stage.reason or stage.status}"
        for stage in report.stages
        if stage.id in report.assessment.gaps
    ]


def finding_actions(report: ScanReport) -> list[str]:
    findings = sorted(
        (finding for stage in report.stages for finding in stage.findings),
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.line, f.rule),
    )
    return [
        f"Review {f.rule} at {f.path or 'repository'}:{f.line}: {f.message}"
        for f in findings
        if SEVERITY_ORDER[f.severity] >= 2
    ]


def next_actions(report: ScanReport) -> list[str]:
    actions = [f"Resolve blocker: {reason}" for reason in report.assessment.blockers]
    actions.extend(missing_actions(report))
    actions.extend(finding_actions(report))
    if report.omitted_stages:
        actions.append("Run --profile full to include: " + ", ".join(report.omitted_stages))
    if not actions:
        actions.append(
            "Read the tests, dependency policy and maintainer history before adopting or merging."
        )
    return actions
