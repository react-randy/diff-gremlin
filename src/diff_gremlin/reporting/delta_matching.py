"""Pair observations only when identity and multiplicity support the match."""

from collections import defaultdict, deque
from dataclasses import asdict

from diff_gremlin.domain.findings import SEVERITY_ORDER, Finding, observation_identity

type ChangedLines = dict[str, tuple[tuple[int, int], ...]]


def identity(finding: Finding) -> str:
    return observation_identity(
        finding.rule,
        finding.path,
        finding.symbol,
        finding.message,
        finding.metric,
        finding.fingerprint,
    )


def located(finding: Finding, lines: ChangedLines | None) -> dict:
    result = asdict(finding)
    result["in_changed_lines"] = (
        None
        if lines is None or not finding.path or finding.line < 1
        else any(
            start <= finding.line <= end for start, end in lines.get(finding.path, ())
        )
    )
    return result


def _observation(finding: Finding) -> tuple:
    return (
        finding.severity,
        finding.metric,
        finding.value,
        "" if finding.metric else finding.message,
    )


def changed(
    before: Finding,
    after: Finding,
    base_lines: ChangedLines | None,
    head_lines: ChangedLines | None,
) -> dict:
    measurement = None
    direction = "changed"
    if (
        before.metric
        and before.metric == after.metric
        and before.value is not None
        and after.value is not None
    ):
        difference = after.value - before.value
        measurement = {
            "metric": before.metric,
            "base": before.value,
            "head": after.value,
            "delta": round(difference, 4),
        }
        direction = (
            "worsened"
            if difference > 0
            else "improved"
            if difference < 0
            else "changed"
        )
    if before.severity != after.severity:
        direction = (
            "worsened"
            if SEVERITY_ORDER[after.severity] > SEVERITY_ORDER[before.severity]
            else "improved"
        )
    return {
        "identity": identity(after),
        "base": located(before, base_lines),
        "head": located(after, head_lines),
        "measurement": measurement,
        "severity": {"base": before.severity, "head": after.severity},
        "direction": direction,
    }


def match_findings(
    base: list[Finding],
    head: list[Finding],
    *,
    base_lines: ChangedLines | None = None,
    head_lines: ChangedLines | None = None,
) -> dict:
    before: dict[str, list[Finding]] = defaultdict(list)
    after: dict[str, list[Finding]] = defaultdict(list)
    for finding in base:
        before[identity(finding)].append(finding)
    for finding in head:
        after[identity(finding)].append(finding)
    added, resolved, changes, ambiguous = [], [], [], []
    unchanged = 0
    for key in sorted(before.keys() | after.keys()):
        old, new = before[key], after[key]
        # Equal observations can be accounted for by multiplicity. A changed
        # duplicate cannot be attributed to a particular function without proof.
        duplicate = len(old) > 1 or len(new) > 1
        observations: dict[tuple, deque[Finding]] = defaultdict(deque)
        for finding in new:
            observations[_observation(finding)].append(finding)
        residual = []
        for finding in old:
            candidates = observations[_observation(finding)]
            if candidates:
                candidates.popleft()
                unchanged += 1
            else:
                residual.append(finding)
        old = residual
        new = [
            finding for candidates in observations.values() for finding in candidates
        ]
        is_ambiguous = duplicate and bool(old or new)
        if old and new and not duplicate:
            changes.append(changed(old.pop(), new.pop(), base_lines, head_lines))
        elif is_ambiguous:
            ambiguous.append(key)
        added.extend(located(item, head_lines) for item in new)
        if not is_ambiguous:
            resolved.extend(located(item, base_lines) for item in old)
    return {
        "added_findings": added,
        "resolved_findings": resolved,
        "changed_findings": changes,
        "unchanged_findings": unchanged,
        "ambiguous_identities": ambiguous,
        "uncertain_identities": _body_replacements(added, resolved),
    }


def _body_replacements(added: list[dict], resolved: list[dict]) -> list[str]:
    previous = {
        (item["rule"], item["path"], item["metric"])
        for item in resolved
        if item["identity_kind"] == "body"
    }
    return sorted(
        {
            item["fingerprint"]
            for item in added
            if item["identity_kind"] == "body"
            and (item["rule"], item["path"], item["metric"]) in previous
        }
    )
