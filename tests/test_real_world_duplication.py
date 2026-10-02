"""Native incidence statistics and upstream coordinate defects stay distinct."""

import copy
import json
from pathlib import Path

import pytest

from diff_gremlin.analyzers.javascript.duplication import analyze_js_duplication
from diff_gremlin.analyzers.javascript.duplication_statistics import (
    format_catalog,
    source_ids,
    statistic_row,
)
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.policy.blockers import metric_blockers
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.process import run

LONG = (
    "export function compute(input: number): number {\n"
    + "".join(f" const value{i} = input * {i + 2};\n" for i in range(30))
    + " return value0;\n}\n"
)


@pytest.fixture
def context(tmp_path):
    serial = 0

    def make(sources, mutate=None):
        nonlocal serial
        serial += 1
        root = tmp_path / str(serial)
        root.mkdir()
        files, reports = [], []
        for name, text in sources:
            path = root / name
            path.write_text(text, encoding="utf-8")
            files.append(
                SourceFile(path, name, "typescript", False, path.stat().st_size)
            )

        def capture(command, **kwargs):
            result = run(command, **kwargs)
            report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
            data = json.loads(report.read_text())
            reports.append(copy.deepcopy(data))
            if mutate:
                mutate(data)
                report.write_text(json.dumps(data))
            return result

        ctx = ScanContext(
            root, tuple(files), tuple(files), ("typescript",), "full", 30, root, capture
        )
        return ctx, reports

    return make


@pytest.fixture
def native_report(context):
    ctx, reports = context([("a.ts", LONG), ("b.ts", LONG)])
    result = analyze_js_duplication(ctx)
    assert result.status == "ok", result.reason
    return reports[0]


def validate(data):
    return source_ids(
        data["statistics"],
        set(data["detector_files"]),
        data["duplicates"],
        format_catalog(data["tokenizer_formats"]),
    )


def test_native_overlapping_same_file_clone_incidence_exceeds_one_hundred(context):
    ctx, reports = context([("repeated.ts", LONG * 8)])
    result = analyze_js_duplication(ctx)
    assert result.status == "ok", result.reason
    report = reports[0]
    source = next(
        iter(report["statistics"]["formats"]["typescript"]["sources"].values())
    )
    assert source["percentage"] > 100
    assert source["clones"] == 2 * len(report["duplicates"])
    assert (
        result.metrics["duplication_percent"]
        == report["statistics"]["total"]["percentage"]
    )
    assert result.metrics["measure"] == "jscpd-native-clone-incidence-v1"
    assert result.metrics["clone_groups"] == 1
    assert len(result.findings) == 2


def test_native_embedded_css_maps_retain_original_source_identity(context):
    source = (
        "export const style = <style>\n"
        + "".join(f".class{i} {{ color: red; display: block; }}\n" for i in range(30))
        + "</style>;\n"
    )
    ctx, reports = context([("style.tsx", source)])
    result = analyze_js_duplication(ctx)
    assert result.status == "ok", result.reason
    assert set(reports[0]["statistics"]["formats"]) == {"css", "tsx"}
    assert result.metrics["native_source_maps"] == 2
    assert result.analyzed_files == result.eligible_files == 1


@pytest.mark.parametrize(
    "value", [True, -1, float("nan"), float("inf"), 10**400, "50", None]
)
def test_native_ratio_invalid_values_remain_failed(native_report, value):
    row = native_report["statistics"]["total"]
    row["percentage"] = value
    with pytest.raises((TypeError, ValueError)):
        statistic_row(row)


@pytest.mark.parametrize("field", ["percentage", "percentageTokens"])
def test_native_ratio_must_match_counters(native_report, field):
    native_report["statistics"]["total"][field] += 0.01
    with pytest.raises(ValueError, match="ratio disagrees"):
        validate(native_report)


@pytest.mark.parametrize(
    "field",
    ["clones", "duplicatedLines", "duplicatedTokens", "lines", "tokens", "sources"],
)
@pytest.mark.parametrize("value", [True, -1, 2**53])
def test_native_counters_require_safe_nonnegative_integers(native_report, field, value):
    native_report["statistics"]["total"][field] = value
    with pytest.raises(ValueError):
        validate(native_report)


def test_native_coherent_but_forged_incidence_counter_remains_failed(native_report):
    row = native_report["statistics"]["total"]
    row["clones"] += 1
    with pytest.raises(ValueError, match="clone counters"):
        validate(native_report)


def test_native_source_counter_cannot_drop_second_occurrence(native_report):
    row = next(
        iter(native_report["statistics"]["formats"]["typescript"]["sources"].values())
    )
    row["clones"] = 0
    with pytest.raises(ValueError, match="clone counters"):
        validate(native_report)


@pytest.mark.parametrize(
    "variant", ["missing", "duplicate", "unknown", "foreign", "clone-format"]
)
def test_native_catalog_and_embedded_maps_reject_spoofing(native_report, variant):
    if variant == "missing":
        native_report["tokenizer_formats"] = None
    elif variant == "duplicate":
        native_report["tokenizer_formats"][0] = native_report["tokenizer_formats"][1]
    elif variant == "unknown":
        formats = native_report["statistics"]["formats"]
        formats["invented-format"] = formats.pop("typescript")
    elif variant == "foreign":
        sources = native_report["statistics"]["formats"]["typescript"]["sources"]
        sources["/foreign.ts"] = sources.pop(next(iter(sources)))
    else:
        native_report["duplicates"][0]["format"] = "css"
    with pytest.raises((TypeError, ValueError)):
        validate(native_report)


def corrupt_second_end(data):
    location = data["duplicates"][0]["secondFile"]
    location["end"] = location["endLoc"]["line"] = 999999


def test_native_cross_source_hash_extension_retains_only_verified_clones(context):
    lines = LONG.splitlines(keepends=True)
    ctx, reports = context(
        [("a.ts", LONG), ("b.ts", "".join(lines[:22])), ("c.ts", "".join(lines[10:]))]
    )
    result = analyze_js_duplication(ctx)
    assert result.status == "limited", result.reason
    assert len(reports[0]["duplicates"]) == 2
    assert result.metrics["verified_clone_groups"] == 1
    assert result.metrics["rejected_clone_groups"] == 1
    assert len(result.findings) == 2
    assert "duplication_percent" not in result.metrics
    assert result.analyzed_files == result.eligible_files == 3
    assert stage_score(result) is None


def test_recognized_second_coordinate_defect_retains_unscored_native_evidence(context):
    ctx, _ = context([("a.ts", LONG), ("b.ts", LONG)], corrupt_second_end)
    result = analyze_js_duplication(ctx)
    assert result.status == "limited", result.reason
    assert result.analyzed_files == result.eligible_files == 2
    assert result.findings == []
    assert result.metrics["rejected_clone_groups"] == 1
    assert result.metrics["verified_clone_groups"] == 0
    assert result.metrics["native_duplication_incidence_percent"] == 50
    assert "duplication_percent" not in result.metrics
    assert stage_score(result) is None
    assert "native coordinate defect" in result.reason


def test_rejected_incidence_above_threshold_cannot_supply_policy_blocker(context):
    ctx, _ = context([("repeated.ts", LONG * 8)], corrupt_second_end)
    result = analyze_js_duplication(ctx)
    assert result.status == "limited", result.reason
    assert result.metrics["native_duplication_incidence_percent"] > 60
    assert metric_blockers(result) == []
    assert stage_score(result) is None


@pytest.mark.parametrize(
    "field,value",
    [("start", True), ("end", 0), ("name", "/foreign.ts"), ("startLoc", None)],
)
def test_second_location_schema_and_identity_corruption_remain_failed(
    context, field, value
):
    def mutate(data):
        data["duplicates"][0]["secondFile"][field] = value

    ctx, _ = context([("a.ts", LONG), ("b.ts", LONG)], mutate)
    result = analyze_js_duplication(ctx)
    assert result.status == "failed", result.reason
    assert result.metrics == {} and result.findings == []
