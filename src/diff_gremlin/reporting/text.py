"""Compact terminal output without terminal-controlled source strings."""

from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.reporting.advice import next_actions
from diff_gremlin.reporting.escaping import plain
from diff_gremlin.reporting.provenance import revision_label


def render(report: ScanReport) -> str:
    a = report.assessment
    score = "unknown" if a.score is None else f"{a.score:g}/100 ({a.grade})"
    lines = [
        f"Diff Gremlin · {score} · {a.decision}",
        f"{plain(report.source.target)} @ {plain(revision_label(report.source))}",
        f"Profile {report.profile}; required evidence {a.completed_stages}/{a.required_stages}; {report.duration_seconds:.2f}s",
        "",
    ]
    lines.extend(
        f"{stage.status:11} {stage.id} ({stage.analyzed_files}/{stage.eligible_files} files) {plain(stage.reason)}"
        for stage in report.stages
    )
    lines += ["", "Findings:"]
    lines.extend(
        f"  {f.severity:8} {plain(f.path)}:{f.line} {plain(f.rule)} — {plain(f.message)}"
        for stage in report.stages
        for f in stage.findings
    )
    lines += ["", "Next:"] + ["  " + plain(action) for action in next_actions(report)]
    return "\n".join(lines) + "\n"
