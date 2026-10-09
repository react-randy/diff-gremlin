"""Gate demonstrable comparison regressions under the existing blocker policy."""

from collections import defaultdict
from math import isfinite

from diff_gremlin.domain.findings import Finding, observation_identity
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.policy.gates import Gates, exit_code
from diff_gremlin.policy.metrics import number

COMPARISON_POLICY_VERSION = "1.0.0"
COMPLEXITY_MEASURES = frozenset(
    {"cyclomatic_complexity", "shell-ast-decision-complexity-v1"}
)


def _complexity_blocker(metric: str, value: object) -> bool:
    """Apply the existing threshold to supported, explicitly named measures."""
    return (
        metric in COMPLEXITY_MEASURES
        and isinstance(value, (int, float))
        and not isinstance(value, bool)
        and isfinite(value)
        and value > 50
    )


def _finding_key(finding: Finding) -> str:
    return observation_identity(
        finding.rule,
        finding.path,
        finding.symbol,
        finding.message,
        finding.metric,
        finding.fingerprint,
    )


def _limited_regressions(
    base: StageResult, head: StageResult, delta: dict
) -> list[str]:
    """Partial coverage can prove a located worsening, never absence or resolution."""
    if (
        base.status not in {"ok", "limited"}
        or head.status not in {"ok", "limited"}
        or (base.tool, base.version, base.scope, base.category)
        != (head.tool, head.version, head.scope, head.category)
    ):
        return []
    previous: dict[str, list[Finding]] = defaultdict(list)
    for finding in base.findings:
        previous[_finding_key(finding)].append(finding)
    result = []
    uncertain = set(delta["ambiguous_identities"]) | set(delta["uncertain_identities"])
    for finding in head.findings:
        key = _finding_key(finding)
        if key in uncertain:
            continue
        old = previous[key]
        if len(old) == 1:
            known_worsening = (
                finding.metric == old[0].metric
                and finding.value is not None
                and old[0].value is not None
                and _complexity_blocker(finding.metric, finding.value)
                and finding.value > old[0].value
            ) or (finding.severity == "critical" and old[0].severity != "critical")
        else:
            known_worsening = (
                not old
                and base.status == "ok"
                and (
                    finding.severity == "critical"
                    or _complexity_blocker(finding.metric, finding.value)
                )
            )
        if known_worsening:
            result.append(
                f"{head.id}: new/worsened blocking observation {finding.rule}"
            )
    if base.status == "ok" and head.category == "complexity":
        result.extend(_metric_regressions(base, head))
    return result


def _measurement_regressions(delta: dict) -> list[str]:
    result = []
    uncertain = set(delta["ambiguous_identities"]) | set(delta["uncertain_identities"])
    for finding in delta["added_findings"]:
        key = observation_identity(
            finding["rule"],
            finding["path"],
            finding["symbol"],
            finding["message"],
            finding.get("metric", ""),
            finding["fingerprint"],
        )
        if key in uncertain:
            continue
        if (
            _complexity_blocker(finding.get("metric", ""), finding.get("value"))
        ) or finding["severity"] == "critical":
            result.append(f"{delta['id']}: new blocking observation {finding['rule']}")
    for finding in delta["changed_findings"]:
        measurement = finding["measurement"]
        if (
            measurement
            and _complexity_blocker(measurement["metric"], measurement["head"])
            and measurement["delta"] > 0
        ) or (
            finding["head"]["severity"] == "critical"
            and finding["base"]["severity"] != "critical"
        ):
            result.append(
                f"{delta['id']}: worsened blocking observation {finding['head']['rule']}"
            )
    return result


def _metric_regressions(base: StageResult, head: StageResult) -> list[str]:
    thresholds = {
        "complexity": ("max_cc", 50),
        "duplication": ("duplication_percent", 60),
    }
    if head.category in thresholds:
        key, threshold = thresholds[head.category]
        before, after = number(base, key), number(head, key)
        if (
            before is not None
            and after is not None
            and after > threshold
            and after > before
        ):
            return [f"{head.id}: {key} worsened from {before:g} to {after:g}"]
    if head.category == "hygiene":
        before, after = base.metrics.get("checks"), head.metrics.get("checks")
        if (
            isinstance(before, dict)
            and isinstance(after, dict)
            and before.get("license_file") is True
            and after.get("license_file") is False
        ):
            return [
                f"{head.id}: license file no longer observed; adoption terms need review"
            ]
    return []


def _observed_changes(delta: dict) -> tuple[list[str], list[str]]:
    worsening, improvements = [], []
    if delta["added_findings"]:
        worsening.append(
            f"{delta['id']}: {len(delta['added_findings'])} added observations"
        )
    if delta["resolved_findings"]:
        improvements.append(
            f"{delta['id']}: {len(delta['resolved_findings'])} resolved observations"
        )
    for change in delta["changed_findings"]:
        if change["direction"] == "worsened":
            worsening.append(
                f"{delta['id']}: worsened observation {change['head']['rule']}"
            )
        elif change["direction"] == "improved":
            improvements.append(
                f"{delta['id']}: improved observation {change['head']['rule']}"
            )
    for key in (
        "max_cc",
        "duplication_percent",
        "error_count",
        "warning_count",
        "issue_count",
    ):
        measurement = delta["metrics"].get(key)
        if measurement and measurement["delta"]:
            target = worsening if measurement["delta"] > 0 else improvements
            target.append(
                f"{delta['id']}: {key} changed from {measurement['base']} to {measurement['head']}"
            )
    return worsening, improvements


def delta_assessment(base: ScanReport, head: ScanReport, deltas: list[dict]) -> dict:
    before = {stage.id: stage for stage in base.stages}
    after = {stage.id: stage for stage in head.stages}
    blocking, regressions, improvements, unchanged, unknown = [], [], [], [], []
    required_unknown = False
    for delta in deltas:
        stage_id = delta["id"]
        if not delta["comparable"]:
            unknown.append(f"{stage_id}: {delta['resolution_note']}")
            required_unknown |= any(
                stage is not None and stage.required
                for stage in (before.get(stage_id), after.get(stage_id))
            )
            if (
                base.profile == head.profile
                and stage_id in before
                and stage_id in after
            ):
                known = _limited_regressions(before[stage_id], after[stage_id], delta)
                blocking.extend(known)
                regressions.extend(known)
            continue
        known = _measurement_regressions(delta) + _metric_regressions(
            before[stage_id], after[stage_id]
        )
        blocking.extend(known)
        regressions.extend(known)
        worse, better = _observed_changes(delta)
        regressions.extend(worse)
        improvements.extend(better)
        old_checks, new_checks = (
            before[stage_id].metrics.get("checks"),
            after[stage_id].metrics.get("checks"),
        )
        license_improved = (
            isinstance(old_checks, dict)
            and isinstance(new_checks, dict)
            and old_checks.get("license_file") is False
            and new_checks.get("license_file") is True
        )
        if license_improved:
            improvements.append(f"{stage_id}: license file now observed")
        if not worse and not better and not known and not license_improved:
            unchanged.append(stage_id)
        if delta["ambiguous_identities"]:
            unknown.append(
                f"{stage_id}: duplicate function identities cannot be paired"
            )
            required_unknown = True
        if delta["uncertain_identities"]:
            unknown.append(
                f"{stage_id}: changed anonymous bodies cannot establish function continuity"
            )
            required_unknown = True
    complete = (
        base.assessment.complete and head.assessment.complete and not required_unknown
    )
    decision = (
        "hold"
        if blocking
        else "unknown"
        if not complete
        else "review"
        if regressions
        else "no_configured_regressions"
    )
    return {
        "policy_version": COMPARISON_POLICY_VERSION,
        "complete": complete,
        "decision": decision,
        "blockers": sorted(set(blocking)),
        "regressions": sorted(set(regressions)),
        "improvements": sorted(set(improvements)),
        "unchanged": unchanged,
        "unknown": unknown,
    }


def comparison_exit_code(
    base_report: ScanReport, head_report: ScanReport, document: dict, gates: Gates
) -> int:
    """Known regression/explicit head gate is 1; incomplete comparisons are 3."""
    assessment = document["delta_assessment"]
    if assessment["blockers"]:
        return 1
    if gates.fail_on is not None or gates.fail_under is not None:
        head_code = exit_code(head_report.assessment, head_report.stages, gates)
        if head_code:
            return head_code
    if (
        not base_report.assessment.complete
        or not head_report.assessment.complete
        or not assessment["complete"]
    ):
        return 3
    return 0
