"""Human review changes followed by the complete head receipt."""

from collections.abc import Callable

from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.reporting import comparison_summary as summary
from diff_gremlin.reporting import markdown, text
from diff_gremlin.reporting.escaping import markdown as escape
from diff_gremlin.reporting.escaping import plain
from diff_gremlin.reporting.summary import FINDING_LIMIT, truncation_note


def table(headers: tuple[str, ...], rows: list[tuple]) -> list[str]:
    return [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
        *("| " + " | ".join(escape(cell) for cell in row) + " |" for row in rows),
    ]


def finding_lines(document: dict, *, rich: bool) -> list[str]:
    safe = escape if rich else plain
    lines = []
    for key, label in (
        ("added_findings", "New observations"),
        ("resolved_findings", "Confirmed resolutions"),
    ):
        lines.extend([f"{'## ' if rich else ''}{label}", ""])
        rows = summary.finding_rows(document, key)
        lines.extend(
            f"- {safe(severity)} · {safe(location)} · {safe(stage)} · {safe(rule)} — {safe(message)}"
            for severity, stage, location, rule, message in rows[:FINDING_LIMIT]
        )
        if note := truncation_note(len(rows), FINDING_LIMIT, label.lower()):
            lines.append(note)
        if not rows:
            lines.append("None observed. Read the coverage and resolution notes.")
        lines.append("")
    return lines


def identity_lines(document: dict, *, rich: bool) -> list[str]:
    safe: Callable[[object], str] = escape if rich else plain
    lines = ["# Diff Gremlin comparison" if rich else "Diff Gremlin comparison", ""]
    assessment = document.get("delta_assessment")
    if assessment is not None:
        lines.extend(
            [
                f"Delta decision: {safe(assessment['decision'])}",
                "Comparison evidence: "
                + ("complete" if assessment["complete"] else "incomplete; inspect gaps"),
            ]
        )
        lines.extend("- " + safe(reason) for reason in assessment["blockers"])
        lines.append("")
    for side in ("base", "head"):
        receipt = document[side]
        lines.extend(
            [
                f"{side.title()}: {safe(receipt['source']['commit_sha'])}",
                safe(summary.receipt_summary(receipt)),
                "",
            ]
        )
    return [*lines, safe(document["comparison_semantics"]), ""]


def changed_lines(document: dict, *, rich: bool) -> list[str]:
    safe = escape if rich else plain
    changes = [
        (delta["id"], change)
        for delta in document["deltas"]
        for change in delta.get("changed_findings", [])
    ]
    if not changes:
        return []
    lines = ["## Changed observations" if rich else "Changed observations", ""]
    for stage, change in changes[:FINDING_LIMIT]:
        finding = change["head"]
        location = f"{finding['path']}:{finding['line']}:{finding['column']}"
        measurement = change.get("measurement")
        detail = (
            f"{measurement['metric']}: {measurement['base']} → {measurement['head']}"
            if measurement is not None
            else change["direction"]
        )
        lines.append(
            f"- {safe(location)} · {safe(stage)} · {safe(finding['symbol'] or finding['rule'])} — {safe(detail)}"
        )
    if note := truncation_note(len(changes), FINDING_LIMIT, "changed observations"):
        lines.append(note)
    return [*lines, ""]


def evidence_lines(document: dict, *, rich: bool) -> list[str]:
    stages, metrics = summary.stage_rows(document), summary.metric_rows(document)
    lines = ["## Stage changes" if rich else "Stage changes", ""]
    if rich:
        lines.extend(table(("Stage", "Evidence", "Score", "Findings"), stages))
    else:
        lines.extend(plain(" · ".join(row)) for row in stages)
    lines.extend(["", "## Changed metrics" if rich else "Changed metrics", ""])
    if rich and metrics:
        lines.extend(table(("Stage", "Metric", "Base", "Head", "Change"), metrics))
    else:
        lines.extend(
            plain(f"{stage} · {name}: {before} → {after} ({change})")
            for stage, name, before, after, change in metrics
        )
    if not metrics:
        lines.append(
            "No numeric changes in stages with complete evidence on both sides."
        )
    return [*lines, ""]


def render(document: dict, head: ScanReport, *, format: str) -> str:
    rich = format == "markdown"
    safe = escape if rich else plain
    lines = identity_lines(document, rich=rich) + evidence_lines(document, rich=rich)
    lines += changed_lines(document, rich=rich)
    lines += finding_lines(document, rich=rich)
    notes = summary.resolution_notes(document)
    if notes:
        lines += ["## Resolution limits" if rich else "Resolution limits", ""]
        lines += ["- " + safe(note) for note in notes] + [""]
    lines += ["Complete head receipt follows.", "", "---" if rich else "", ""]
    receipt = markdown.render(head) if rich else text.render(head)
    return "\n".join(lines) + receipt
