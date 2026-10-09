"""Comparison receipt, selection and progress contracts visible to CLI users."""

import json
from pathlib import Path

import pytest

from diff_gremlin.cli.output import render
from diff_gremlin.cli.parser import parser
from diff_gremlin.cli.progress import stage_progress
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.domain.sources import Snapshot, SourceIdentity
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.orchestration import scan as scan_module
from diff_gremlin.orchestration.selection import Capability
from diff_gremlin.policy.assessment import assess
from diff_gremlin.reporting.delta import compare_document


def report(stage: StageResult) -> ScanReport:
    return ScanReport(
        SourceIdentity("fixture", "fixture", "a" * 40),
        "quick",
        (),
        [stage],
        assess([stage]),
        1,
    )


def test_compact_receipt_preserves_verdict_and_stage_context():
    stage = StageResult(
        "lint", "Lint", "lint", "missing", "fixture", reason="Tool absent"
    )
    before, after = report(stage), report(stage)
    document = compare_document(before, after)
    # The projection is independent of the delta policy's decision logic.
    document["delta_assessment"] = {"decision": "unknown", "complete": False}
    compact = json.loads(render(after, "json-delta", document))
    assert compact["mode"] == "comparison-delta"
    assert "base" not in compact and "head" not in compact
    assert compact["sources"]["head"]["commit_sha"] == "a" * 40
    assert compact["delta_assessment"]["decision"] == "unknown"
    assert compact["deltas"][0]["head_status"] == "missing"
    assert compact["coverage"]["head"]["completed_stages"] == 0


@pytest.mark.parametrize("command", ["compare", "pr"])
def test_comparison_options_are_discoverable(command):
    arguments = [command, ".", "main", "HEAD"] if command == "compare" else [command, "URL"]
    args = parser().parse_args(
        [*arguments, "--paths", "app", "--paths", "ui", "--changed-paths", "--format", "json-delta", "--quiet"]
    )
    assert args.paths == ["app", "ui"] and args.changed_paths and args.quiet


@pytest.mark.parametrize("arguments", [["--paths", "app"], ["--changed-paths"], ["--format", "json-delta"]])
def test_check_rejects_comparison_only_options(arguments):
    with pytest.raises(SystemExit) as error:
        parser().parse_args(["check", ".", *arguments])
    assert error.value.code == 2


def test_progress_reaches_reader_before_next_capability(tmp_path, monkeypatch, capsys):
    snapshot = Snapshot(tmp_path, SourceIdentity("fixture", "fixture"))
    events = []
    output = stage_progress(side="base")
    assert output is not None

    def notify(stage):
        events.append(stage.id)
        output(stage)

    def first(context):
        assert events == ["inventory"]
        assert "base inventory: ok" in capsys.readouterr().err
        return [
            StageResult("first.one", "One", "structure", "ok", "fixture"),
            StageResult("first.two", "Two", "structure", "ok", "fixture"),
        ]

    def second(context):
        assert events == ["inventory", "first.one", "first.two"]
        assert "base first.two: ok" in capsys.readouterr().err
        raise ValueError("controlled failure")

    monkeypatch.setattr(
        scan_module,
        "capabilities",
        lambda languages: [
            Capability("first", "First", "structure", first),
            Capability("second", "Second", "structure", second),
        ],
    )
    result = scan_module.scan(snapshot, profile="full", progress=notify)
    assert events == ["inventory", "first.one", "first.two", "second", "history.git"]
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "base second: failed" in captured.err
    assert "base history.git: unsupported" in captured.err
    assert not result.assessment.complete


def test_library_is_silent_and_cli_can_suppress_progress(tmp_path, capsys):
    assert stage_progress(quiet=True) is None
    stage = StageResult("bad\x1b[31m\nstage", "Stage", "structure", "ok", "fixture")
    notify = stage_progress(side="head")
    assert notify is not None
    notify(stage)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "\x1b" not in captured.err
    assert len(captured.err.splitlines()) == 1


def test_selection_makes_scan_partial_and_skips_unscoped_history(tmp_path, monkeypatch):
    from dataclasses import replace

    snapshot = Snapshot(tmp_path, SourceIdentity("fixture", "fixture"), Path("history"))
    snapshot = replace(snapshot, selection={"partial": True, "mode": "changed-paths"})
    monkeypatch.setattr(scan_module, "capabilities", lambda languages: [])
    result = scan_module.scan(snapshot, profile="full")
    assert not result.assessment.complete
    assert result.source_selection["partial"]
    assert next(s for s in result.stages if s.id == "history.git").status == "unsupported"
