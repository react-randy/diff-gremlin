"""Choose a projection without contaminating machine stdout."""

from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.reporting import comparison, markdown, text
from diff_gremlin.reporting.serialization import json_text, report_document


def render(report: ScanReport, format: str, comparison_document: dict | None = None) -> str:
    if format == "json":
        return json_text(comparison_document or report_document(report))
    if comparison_document is not None:
        return comparison.render(comparison_document, report, format=format)
    return markdown.render(report) if format == "markdown" else text.render(report)
