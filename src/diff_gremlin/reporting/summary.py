"""Project a compact human view from the complete evidence receipt."""

from diff_gremlin.domain.assessment import Assessment
from diff_gremlin.domain.findings import SEVERITY_ORDER, Finding
from diff_gremlin.domain.reports import ScanReport

FINDING_LIMIT = 20
ACTION_LIMIT = 10


def score_label(assessment: Assessment) -> str:
    """Label a partial score beside its provisional evidence status."""
    if assessment.score is not None:
        return f"{assessment.score:g}/100 ({assessment.grade})"
    observed = assessment.observed
    if observed is not None and observed.score is not None:
        return f"observed {observed.score:g}/100 ({observed.grade}) · provisional"
    return "unknown"


def coverage_label(assessment: Assessment) -> str:
    """Stage and weight coverage describe different evidence boundaries."""
    text = f"Required evidence {assessment.completed_stages}/{assessment.required_stages} stages"
    if not assessment.complete:
        text += "; strict score unknown"
    observed = assessment.observed
    if observed is not None:
        text += f"; measured category weight {observed.contributing_weight}/{observed.applicable_weight}"
        if observed.partial_categories:
            text += "; partial categories: " + ", ".join(observed.partial_categories)
    return text


def prioritized_findings(report: ScanReport) -> list[Finding]:
    """Put the most consequential located findings first without losing receipts."""
    return sorted(
        (finding for stage in report.stages for finding in stage.findings),
        key=lambda finding: (
            -SEVERITY_ORDER[finding.severity],
            finding.path,
            finding.line,
            finding.rule,
        ),
    )


def truncation_note(total: int, shown: int, label: str) -> str:
    """Tell readers where every remaining observation can be inspected."""
    if total <= shown:
        return ""
    return f"Showing {shown} of {total} {label}; --format json includes every item."


def asset_label(report: ScanReport) -> str:
    """Separate declared binary assets from missing source evidence."""
    inventory = next(
        (stage for stage in report.stages if stage.id == "inventory"), None
    )
    if inventory is None:
        return ""
    binary = inventory.metrics.get("binary_asset_files", 0)
    omitted = inventory.metrics.get("omitted_possible_source_files", 0)
    if not binary and not omitted:
        return ""
    return (
        f"Source scope: {binary} binary assets outside text analysis; "
        f"{omitted} possible source files omitted. JSON inventory includes paths and reasons."
    )
