"""Compact terminal output without terminal-controlled source strings."""

from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.reporting.advice import next_actions
from diff_gremlin.reporting.escaping import plain
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


def render(report: ScanReport) -> str:
    a = report.assessment
    lines = [
        f"Diff Gremlin · {score_label(a)} · {a.decision}",
        f"{plain(report.source.target)} @ {plain(revision_label(report.source))}",
        f"Profile {report.profile}; {coverage_label(a)}; {report.duration_seconds:.2f}s",
        "",
    ]
    if scope := asset_label(report):
        lines.extend([scope, ""])
    lines.extend(
        f"{stage.status:11} {stage.id} ({stage.analyzed_files}/{stage.eligible_files} files) {plain(stage.reason)}"
        for stage in report.stages
    )
    findings = prioritized_findings(report)
    lines += ["", f"Findings ({len(findings)}):"]
    lines.extend(
        f"  {f.severity:8} {plain(f.path)}:{f.line} {plain(f.rule)} — {plain(f.message)}"
        for f in findings[:FINDING_LIMIT]
    )
    if note := truncation_note(len(findings), FINDING_LIMIT, "findings"):
        lines.append(note)
    actions = next_actions(report)
    lines += ["", "Next:"] + ["  " + plain(action) for action in actions[:ACTION_LIMIT]]
    if note := truncation_note(len(actions), ACTION_LIMIT, "next actions"):
        lines.append(note)
    return "\n".join(lines) + "\n"
