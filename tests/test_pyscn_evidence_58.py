"""Native tiny-file clone schemas and independently corrupted clone evidence."""

import json
from dataclasses import replace

import pytest
import test_polyglot

from diff_gremlin.analyzers.python.pyscn import analyze_pyscn
from diff_gremlin.process import run

context = test_polyglot.context


@pytest.mark.parametrize(
    "sources",
    [
        ["def compute(value):\n    return value + 1\n"] * 4,
        ["VALUE = 1\n"] * 4,
        [""] * 4,
        ["class Example:\n    pass\n"] * 4,
    ],
)
def test_native_pyscn_four_tiny_files_preserve_valid_zero_clone_schema(
    context, sources
):
    ctx = context(
        [(f"{number}.py", "python", source) for number, source in enumerate(sources)],
        run,
    )
    stages = analyze_pyscn(ctx)
    assert [stage.status for stage in stages] == ["ok", "ok", "ok"], [
        (stage.id, stage.reason) for stage in stages
    ]
    assert stages[1].metrics == {"duplication_percent": 0.0, "clone_groups": 0}
    assert stages[1].analyzed_files == 4


def _clone_source():
    return (
        "def compute(value):\n    result = 0\n"
        + "".join(f"    result += value * {number}\n" for number in range(1, 16))
        + "    return result\n"
    )


@pytest.mark.parametrize(
    "ending,trailing", [("\n", True), ("\n", False), ("\r\n", True), ("\r\n", False)]
)
def test_native_pyscn_clone_final_line_coordinates(context, ending, trailing):
    source = _clone_source().replace("\n", ending)
    if not trailing:
        source = source.removesuffix(ending)
    ends = []

    def observed(command, **kwargs):
        result = run(command, **kwargs)
        if "analyze" in command and "clones" in command[command.index("--select") + 1]:
            data = json.loads(result.stdout)
            ends.extend(
                fragment["location"]["end_line"]
                for group in data["clone"]["clone_groups"]
                for fragment in group["clones"]
            )
        return result

    stage = analyze_pyscn(
        context([(f"{number}.py", "python", source) for number in range(4)], observed)
    )[1]
    assert ends == [18] * 4
    assert stage.status == "ok", stage.reason
    assert stage.metrics["clone_groups"] == 1 and len(stage.findings) == 4


@pytest.mark.parametrize(
    "corruption", [None, "coverage", "missing-list", "range", "foreign", "percent"]
)
def test_native_pyscn_clone_positive_and_adverse_schema_controls(context, corruption):
    observed_positive = []

    def observed(command, **kwargs):
        result = run(command, **kwargs)
        if (
            "analyze" not in command
            or "clones" not in command[command.index("--select") + 1]
        ):
            return result
        data = json.loads(result.stdout)
        assert data["clone"]["clone_groups"], "Native positive required before mutation"
        observed_positive.append(True)
        if corruption == "coverage":
            data["clone"]["statistics"]["files_analyzed"] = 0
        elif corruption == "missing-list":
            data["clone"].pop("clone_groups")
        elif corruption == "range":
            data["clone"]["clone_groups"][0]["clones"][0]["location"]["end_line"] = (
                999999
            )
        elif corruption == "foreign":
            data["clone"]["clone_groups"][0]["clones"][0]["location"]["file_path"] = (
                "/foreign/private.py"
            )
        elif corruption == "percent":
            data["summary"]["code_duplication_percentage"] = 101
        return replace(result, stdout=json.dumps(data))

    ctx = context(
        [(f"{number}.py", "python", _clone_source()) for number in range(4)], observed
    )
    before = {file.path: file.path.read_bytes() for file in ctx.files}
    stage = analyze_pyscn(ctx)[1]
    assert observed_positive
    assert stage.status == ("failed" if corruption else "ok"), stage.reason
    if corruption:
        assert not stage.metrics and not stage.findings and stage.analyzed_files == 0
        assert "validation:" in stage.reason and "/foreign" not in stage.reason
    else:
        assert stage.metrics == {"duplication_percent": 100.0, "clone_groups": 1}
        assert {finding.path for finding in stage.findings} == {
            f"{number}.py" for number in range(4)
        }
    assert before == {file.path: file.path.read_bytes() for file in ctx.files}
    assert not (ctx.root / ".pyscn").exists()
