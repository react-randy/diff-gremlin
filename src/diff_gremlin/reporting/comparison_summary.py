"""Readable changes projected from the shared comparison receipt."""

from diff_gremlin.domain.findings import SEVERITY_ORDER


def score(value: float | None) -> str:
    return "unknown" if value is None else f"{value:g}/100"


def receipt_summary(receipt: dict) -> str:
    assessment, coverage = receipt["assessment"], receipt["coverage"]
    return (
        f"{score(assessment['score'])} · {assessment['decision']} · "
        f"{coverage['completed_stages']}/{coverage['required_stages']} required stages · "
        f"{receipt['profile']} profile"
    )


def stage_rows(document: dict) -> list[tuple[str, str, str, str]]:
    return [
        (
            delta["id"],
            f"{delta['base_status']} → {delta['head_status']}",
            f"{score(delta['base_score'])} → {score(delta['head_score'])}",
            f"+{len(delta['added_findings'])} observed / -{len(delta['resolved_findings'])} confirmed",
        )
        for delta in document["deltas"]
    ]


def metric_rows(document: dict) -> list[tuple[str, str, str, str, str]]:
    return [
        (
            delta["id"],
            name,
            f"{values['base']:g}",
            f"{values['head']:g}",
            f"{values['delta']:+g}",
        )
        for delta in document["deltas"]
        for name, values in sorted(delta["metrics"].items())
        if values["delta"] != 0
    ]


def finding_rows(document: dict, key: str) -> list[tuple[str, str, str, str, str]]:
    rows = [
        (
            finding["severity"],
            delta["id"],
            f"{finding['path']}:{finding['line']}:{finding['column']}"
            if finding["path"]
            else "repository",
            finding["rule"],
            finding["message"],
        )
        for delta in document["deltas"]
        for finding in delta[key]
    ]
    return sorted(rows, key=lambda row: (-SEVERITY_ORDER[row[0]], row[1:]))


def resolution_notes(document: dict) -> list[str]:
    return [
        f"{delta['id']}: {delta['resolution_note']}"
        for delta in document["deltas"]
        if not delta["comparable"]
    ]
