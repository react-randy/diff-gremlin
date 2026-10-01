"""Human review changes followed by the complete head receipt."""

from collections.abc import Callable

from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.reporting import comparison_summary as summary
from diff_gremlin.reporting import markdown, text
from diff_gremlin.reporting.escaping import markdown as escape
from diff_gremlin.reporting.escaping import plain


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
            for severity, stage, location, rule, message in rows
        )
        if not rows:
            lines.append("None observed. Read the coverage and resolution notes.")
        lines.append("")
    return lines


def identity_lines(document: dict, *, rich: bool) -> list[str]:
    safe: Callable[[object], str] = escape if rich else plain
    lines = ["# Diff Gremlin comparison" if rich else "Diff Gremlin comparison", ""]
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
    lines += finding_lines(document, rich=rich)
    notes = summary.resolution_notes(document)
    if notes:
        lines += ["## Resolution limits" if rich else "Resolution limits", ""]
        lines += ["- " + safe(note) for note in notes] + [""]
    lines += ["Complete head receipt follows.", "", "---" if rich else "", ""]
    receipt = markdown.render(head) if rich else text.render(head)
    return "\n".join(lines) + receipt
