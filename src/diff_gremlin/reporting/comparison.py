"""Human comparison summary followed by complete head evidence."""

from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.reporting import markdown, text
from diff_gremlin.reporting.escaping import plain


def render(document: dict, head: ScanReport, *, format: str) -> str:
    lines = [
        "Diff Gremlin comparison",
        f"Base: {document['base']['source']['commit_sha']}",
        f"Head: {document['head']['source']['commit_sha']}",
        document["comparison_semantics"],
        "",
    ]
    for delta in document["deltas"]:
        added, resolved = len(delta["added_findings"]), len(delta["resolved_findings"])
        lines.append(
            f"{delta['id']}: {delta['base_status']} → {delta['head_status']}; +{added} findings, -{resolved} confirmed resolutions"
        )
    summary = "\n".join(plain(line) for line in lines) + "\n\n"
    if format == "markdown":
        return "```text\n" + summary + "```\n\n" + markdown.render(head)
    return summary + text.render(head)
