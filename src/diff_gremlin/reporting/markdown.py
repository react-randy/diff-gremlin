"""Readable repository receipts with every stage and finding."""

from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.policy.thresholds import POLICY_VERSION
from diff_gremlin.reporting.advice import next_actions
from diff_gremlin.reporting.escaping import markdown as escape
from diff_gremlin.reporting.provenance import revision_label


def summary_lines(report: ScanReport) -> list[str]:
    a = report.assessment
    score = "unknown" if a.score is None else f"{a.score:g}/100 ({a.grade})"
    identity = revision_label(report.source)
    return [
        "# Diff Gremlin",
        "",
        f"**Vibe check: {score} · {escape(a.decision)}**",
        "",
        f"Source: {escape(report.source.target)}",
        f"Commit: {escape(identity)} · profile: {escape(report.profile)} · policy: {POLICY_VERSION}",
        f"Required evidence: {a.completed_stages}/{a.required_stages} stages · {report.duration_seconds:.2f}s",
        "",
    ]


def stage_lines(report: ScanReport) -> list[str]:
    lines = [
        "## Evidence",
        "",
        "| Stage | Status | Score | Files | Tool |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for stage in report.stages:
        score = stage_score(stage)
        lines.append(
            f"| {escape(stage.label)} | {stage.status} | {score if score is not None else '—'} | {stage.analyzed_files}/{stage.eligible_files} | {escape(stage.tool)} {escape(stage.version)} |"
        )
        if stage.reason:
            lines.append(f"| ↳ {escape(stage.id)} | {escape(stage.reason)} | | | |")
    return [*lines, ""]


def finding_lines(report: ScanReport) -> list[str]:
    lines = ["## Findings", ""]
    for stage in report.stages:
        for finding in stage.findings:
            location = (
                f"{finding.path}:{finding.line}" if finding.path else "repository"
            )
            lines.append(
                f"- **{finding.severity}** {escape(location)} — {escape(finding.rule)}: {escape(finding.message)}"
            )
    if len(lines) == 2:
        lines.append("No findings in the observed scope. Check coverage above.")
    return [*lines, ""]


def render(report: ScanReport) -> str:
    lines = summary_lines(report) + stage_lines(report) + finding_lines(report)
    lines += ["## Next actions", ""] + [
        f"- {escape(action)}" for action in next_actions(report)
    ]
    lines += [
        "",
        "Static evidence, not a security certificate or an AI authorship detector.",
        "",
    ]
    return "\n".join(lines)
