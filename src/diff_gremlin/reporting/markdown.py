"""Readable repository receipts with every stage and finding."""

from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.policy.thresholds import POLICY_VERSION
from diff_gremlin.reporting.advice import next_actions
from diff_gremlin.reporting.escaping import markdown as escape
from diff_gremlin.reporting.provenance import revision_label
from diff_gremlin.reporting.summary import (
    ACTION_LIMIT,
    FINDING_LIMIT,
    asset_label,
    coverage_label,
    prioritized_findings,
    score_label,
    truncation_note,
)


def summary_lines(report: ScanReport) -> list[str]:
    a = report.assessment
    identity = revision_label(report.source)
    return [
        "# Diff Gremlin",
        "",
        f"**Vibe check: {score_label(a)} · {escape(a.decision)}**",
        "",
        f"Source: {escape(report.source.target)}",
        f"Commit: {escape(identity)} · profile: {escape(report.profile)} · policy: {POLICY_VERSION}",
        f"{coverage_label(a)} · {report.duration_seconds:.2f}s",
        escape(asset_label(report)),
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
    findings = prioritized_findings(report)
    for finding in findings[:FINDING_LIMIT]:
        location = f"{finding.path}:{finding.line}" if finding.path else "repository"
        lines.append(
            f"- **{finding.severity}** {escape(location)} — {escape(finding.rule)}: {escape(finding.message)}"
        )
    if note := truncation_note(len(findings), FINDING_LIMIT, "findings"):
        lines.extend(["", note])
    if len(lines) == 2:
        lines.append("No findings in the observed scope. Check coverage above.")
    return [*lines, ""]


def render(report: ScanReport) -> str:
    lines = summary_lines(report) + stage_lines(report) + finding_lines(report)
    actions = next_actions(report)
    lines += ["## Next actions", ""] + [
        f"- {escape(action)}" for action in actions[:ACTION_LIMIT]
    ]
    if note := truncation_note(len(actions), ACTION_LIMIT, "next actions"):
        lines.extend(["", note])
    lines += [
        "",
        "Static evidence, not a security certificate or an AI authorship detector.",
        "",
    ]
    return "\n".join(lines)
