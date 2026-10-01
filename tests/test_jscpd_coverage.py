"""Native duplication controls preserve clone windows and source coverage."""

import json
import subprocess
from pathlib import Path

import pytest

from diff_gremlin.analyzers.javascript.duplication import analyze_js_duplication
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.domain.process import RunResult
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.process import trusted_path

SHORT = "export function add(a: number, b: number): number {\n return a + b; }\n"
LONG = (
    "export function compute(input: number): number {\n"
    + "".join(f" const value{i} = input * {i + 2};\n" for i in range(30))
    + " return value0;\n}\n"
)


def native_runner(command, *, cwd, timeout, **kwargs):
    result = subprocess.run(
        command,
        cwd=cwd,
        env={"PATH": trusted_path(cwd), "LANG": "C.UTF-8", "HOME": str(cwd)},
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return RunResult(tuple(command), result.returncode, result.stdout, result.stderr)


@pytest.fixture
def context(tmp_path):
    root, scratch = tmp_path / "source", tmp_path / "scratch"
    root.mkdir()
    scratch.mkdir()

    def make(sources, run=native_runner):
        files = []
        for name, text in sources:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            files.append(SourceFile(path, name, "typescript", False, path.stat().st_size))
        return ScanContext(
            root, tuple(files), tuple(files), ("typescript",), "full", 30, scratch, run
        )

    return make


def test_native_short_input_is_limited_without_a_duplication_score(context):
    result = analyze_js_duplication(context([("short.ts", SHORT)]))
    assert result.status == "limited", result.reason
    assert (result.analyzed_files, result.eligible_files) == (0, 1)
    assert result.metrics["duplication_percent"] == 0
    assert result.metrics["detector_input_files"] == 0
    assert result.metrics["native_source_maps"] == 0
    assert result.metrics["minimum_clone_lines"] == 5
    assert result.metrics["minimum_clone_tokens"] == 50
    assert "5" in result.reason and "50" in result.reason
    assert stage_score(result) is None


def test_native_mixed_input_keeps_both_files_in_eligible_inventory(context):
    result = analyze_js_duplication(context([("short.ts", SHORT), ("long.ts", LONG)]))
    assert result.status == "limited", result.reason
    assert (result.analyzed_files, result.eligible_files) == (1, 2)
    assert result.metrics["duplication_percent"] == 0
    assert result.metrics["analyzed_paths"] == ["long.ts"]
    assert stage_score(result) is None


def test_native_no_duplicate_input_has_complete_zero_evidence(context):
    result = analyze_js_duplication(context([("long.ts", LONG)]))
    assert result.status == "ok", result.reason
    assert (result.analyzed_files, result.eligible_files) == (1, 1)
    assert result.metrics["duplication_percent"] == 0
    assert result.metrics["clone_groups"] == 0
    assert result.metrics["analyzed_paths"] == ["long.ts"]
    assert stage_score(result) == 100


def test_native_source_maps_count_processed_files_without_matching_token_windows(context):
    # Five lines pass Finder's file filter; fewer than fifty tokens yield no clone windows.
    result = analyze_js_duplication(context([("few.ts", "export const value = 1;\n\n\n\n")]))
    assert result.status == "ok", result.reason
    assert (result.analyzed_files, result.eligible_files) == (1, 1)
    assert result.metrics["detector_input_files"] == 1
    assert result.metrics["native_source_maps"] == 1
    assert result.metrics["minimum_clone_tokens"] == 50
    assert result.metrics["duplication_percent"] == 0


def test_native_whitespace_file_has_no_native_source_identity(context):
    result = analyze_js_duplication(context([("empty.ts", "\n" * 5)]))
    assert result.status == "limited", result.reason
    assert (result.analyzed_files, result.eligible_files) == (0, 1)
    assert result.metrics["detector_input_files"] == 1
    assert result.metrics["native_source_maps"] == 0
    assert stage_score(result) is None


@pytest.mark.parametrize("source", ["\n" * 1001, LONG + " " * (101 * 1024)])
def test_native_default_file_caps_remain_explicit_limitations(context, source):
    result = analyze_js_duplication(context([("capped.ts", source)]))
    assert result.status == "limited", result.reason
    assert (result.analyzed_files, result.eligible_files) == (0, 1)
    assert result.metrics["maximum_file_lines"] == 1000
    assert result.metrics["maximum_file_size"] == "100kb"
    assert stage_score(result) is None


def test_native_known_duplicates_survive_the_meaningful_window(context):
    result = analyze_js_duplication(context([("a.ts", LONG), ("b.ts", LONG)]))
    assert result.status == "ok", result.reason
    assert (result.analyzed_files, result.eligible_files) == (2, 2)
    assert result.metrics["duplication_percent"] == 50
    assert result.metrics["clone_groups"] == 1
    assert {finding.path for finding in result.findings} == {"a.ts", "b.ts"}


def test_native_duplicates_with_short_input_preserve_findings_but_limit_score(context):
    result = analyze_js_duplication(context([("a.ts", LONG), ("b.ts", LONG), ("short.ts", SHORT)]))
    assert result.status == "limited", result.reason
    assert (result.analyzed_files, result.eligible_files) == (2, 3)
    assert result.metrics["duplication_percent"] == 50
    assert {finding.path for finding in result.findings} == {"a.ts", "b.ts"}
    assert stage_score(result) is None


def test_empty_inventory_is_skipped_without_running_a_tool(context):
    def forbidden(*args, **kwargs):
        raise AssertionError("Empty inventory must not launch a tool")

    result = analyze_js_duplication(context([], forbidden))
    assert result.status == "skipped"
    assert (result.analyzed_files, result.eligible_files) == (0, 0)
    assert result.metrics == {}


@pytest.mark.parametrize("status,code", [("timeout", None), ("missing", None), ("ok", 2)])
def test_failed_invocations_have_no_observations(context, status, code):
    def fake(command, **kwargs):
        return RunResult(tuple(command), code, status=status)

    result = analyze_js_duplication(context([("long.ts", LONG)], fake))
    assert result.status == (status if status != "ok" else "failed")
    assert result.metrics == {}


def test_previous_report_cannot_substitute_for_this_invocation(context):
    def fake(command, *, cwd, **kwargs):
        old = cwd.parent / "jscpd-report.json"
        old.write_text(json.dumps({"statistics": {"total": {"sources": 1}}, "duplicates": []}))
        return RunResult(tuple(command), 0)

    result = analyze_js_duplication(context([("long.ts", LONG)], fake))
    assert result.status == "failed" and result.metrics == {}


@pytest.mark.parametrize("contents", ["null", "{}", "[]", "{", ""])
def test_current_bad_json_is_not_zero_duplication(context, contents):
    def fake(command, **kwargs):
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        report.parent.mkdir()
        report.write_text(contents)
        return RunResult(tuple(command), 0)

    result = analyze_js_duplication(context([("long.ts", LONG)], fake))
    assert result.status == "failed" and result.metrics == {}


@pytest.mark.parametrize(
    "field,value",
    [
        ("invocation", "previous-invocation"),
        ("options", {"minLines": 1, "minTokens": 1, "maxLines": 1000, "maxSize": "100kb"}),
        ("requested_files", []),
        ("requested_files", ["/outside.ts"]),
        ("detector_files", ["/outside.ts"]),
        ("statistics", None),
        ("duplicates", {}),
    ],
)
def test_valid_native_report_rejects_invocation_or_inventory_tampering(context, field, value):
    def fake(command, **kwargs):
        result = native_runner(command, **kwargs)
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        data = json.loads(report.read_text())
        data[field] = value
        report.write_text(json.dumps(data))
        return result

    result = analyze_js_duplication(context([("long.ts", LONG)], fake))
    assert result.status == "failed" and result.metrics == {}


@pytest.mark.parametrize(
    "field,value",
    [("sources", 0), ("sources", True), ("percentage", float("nan")), ("clones", 1)],
)
def test_valid_native_report_rejects_total_statistic_corruption(context, field, value):
    def fake(command, **kwargs):
        result = native_runner(command, **kwargs)
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        data = json.loads(report.read_text())
        data["statistics"]["total"][field] = value
        report.write_text(json.dumps(data))
        return result

    result = analyze_js_duplication(context([("long.ts", LONG)], fake))
    assert result.status == "failed" and result.metrics == {}


def test_valid_native_report_rejects_same_count_but_wrong_source_identity(context):
    def fake(command, **kwargs):
        result = native_runner(command, **kwargs)
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        data = json.loads(report.read_text())
        sources = data["statistics"]["formats"]["typescript"]["sources"]
        sources["/outside.ts"] = sources.pop(next(iter(sources)))
        report.write_text(json.dumps(data))
        return result

    result = analyze_js_duplication(context([("long.ts", LONG)], fake))
    assert result.status == "failed" and result.metrics == {}


def test_valid_native_report_rejects_clone_outside_observed_inventory(context):
    def fake(command, **kwargs):
        result = native_runner(command, **kwargs)
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        data = json.loads(report.read_text())
        data["duplicates"][0]["firstFile"]["name"] = "/outside.ts"
        report.write_text(json.dumps(data))
        return result

    result = analyze_js_duplication(context([("a.ts", LONG), ("b.ts", LONG)], fake))
    assert result.status == "failed" and result.metrics == {}


def test_previous_native_report_cannot_be_replayed_into_fresh_output(context):
    previous = None

    def fake(command, **kwargs):
        nonlocal previous
        result = native_runner(command, **kwargs)
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        if previous is None:
            previous = report.read_bytes()
        else:
            report.write_bytes(previous)
        return result

    first = analyze_js_duplication(context([("long.ts", LONG)], fake))
    replayed = analyze_js_duplication(context([("long.ts", LONG)], fake))
    assert first.status == "ok", first.reason
    assert replayed.status == "failed" and replayed.metrics == {}
