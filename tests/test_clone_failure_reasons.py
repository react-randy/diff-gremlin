"""Native evidence rejection explains its cause without leaking source bytes."""

import json
from pathlib import Path

import pytest

from diff_gremlin.analyzers.javascript.duplication import analyze_js_duplication
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.process import run

_SOURCE = """export function summarize(values) {
  const output = [];
  for (const value of values) {
    const doubled = value * 2;
    const adjusted = doubled + 17;
    output.push({ value, doubled, adjusted, label: 'sample' });
  }
  return { output, length: values.length, name: 'summary' };
}
"""


@pytest.mark.parametrize(
    "mutation,cause",
    [
        ("none", ""),
        ("range", "clone range outside source lines"),
        ("identity", "different invocation or options"),
        ("missing", "jscpd evidence could not be read"),
    ],
)
def test_native_clone_rejection_preserves_safe_cause(tmp_path, mutation, cause):
    files = []
    for name in ("first.js", "second.js"):
        path = tmp_path / name
        path.write_text(_SOURCE, encoding="utf-8")
        files.append(SourceFile(path, name, "javascript", False, path.stat().st_size))
    scratch = tmp_path / "scratch"
    scratch.mkdir()

    def observed(command, **kwargs):
        result = run(command, **kwargs)
        if "--output" not in command:
            return result
        assert result.status == "ok" and result.returncode == 0
        report = Path(command[command.index("--output") + 1]) / "jscpd-report.json"
        data = json.loads(report.read_bytes())
        assert data["duplicates"], "Real native clone required before corruption"
        if mutation == "range":
            row = data["duplicates"][0]["secondFile"]
            row["start"] = row["end"] + 1
            row["startLoc"]["line"] = row["start"]
        elif mutation == "identity":
            data["invocation"] = "PRIVATE_DIAGNOSTIC_ARGUMENT"
        elif mutation == "missing":
            report.unlink()
            return result
        report.write_text(json.dumps(data), encoding="utf-8")
        return result

    ctx = ScanContext(
        tmp_path,
        tuple(files),
        tuple(files),
        ("javascript",),
        "full",
        30,
        scratch,
        observed,
    )
    result = analyze_js_duplication(ctx)
    if mutation == "none":
        assert result.status == "ok" and result.analyzed_files == 2
        assert result.metrics["clone_groups"] > 0 and result.findings
    else:
        assert result.status == "failed" and result.analyzed_files == 0
        assert result.eligible_files == 2 and result.findings == []
        assert cause in result.reason
    assert "PRIVATE_DIAGNOSTIC_ARGUMENT" not in result.reason
    assert str(tmp_path) not in result.reason
    assert _SOURCE not in result.reason
