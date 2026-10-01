"""Native JDK parse-only controls for Java command argument boundaries."""

import json
import shutil
from dataclasses import asdict
from pathlib import Path

import pytest

from diff_gremlin.analyzers.execution import analyze_execution
from diff_gremlin.domain.context import ScanContext, SourceFile
from diff_gremlin.process import run


def builder(*values):
    return "new ProcessBuilder(" + ", ".join(json.dumps(v) for v in values) + ")"


_CASES = [
    (builder("sh -c SYNTHETIC_SECRET"), "java.process-builder"),
    (builder("sh", "-c SYNTHETIC_SECRET"), "java.process-builder"),
    (builder("printf", "%s", "SYNTHETIC_SECRET"), "java.process-builder"),
    (builder("sh", "-c", "SYNTHETIC_SECRET"), "java.shell-execution"),
    ('new ProcessBuilder(new String[]{"sh -c ordinary"})', "java.process-builder"),
    (
        'new ProcessBuilder(new String[]{"sh", "-c", "ordinary"})',
        "java.shell-execution",
    ),
    ('Runtime.getRuntime().exec("sh -c SYNTHETIC_SECRET")', "java.shell-execution"),
    ('Runtime.getRuntime().exec("  sh\\t-c ordinary  ")', "java.shell-execution"),
    ('Runtime.getRuntime().exec("sh\\f-c ordinary")', "java.shell-execution"),
    ('Runtime.getRuntime().exec("sh\\u000b-c ordinary")', "java.runtime-exec"),
    ('Runtime.getRuntime().exec("sh -c ordinary", null)', "java.shell-execution"),
    ('Runtime.getRuntime().exec("sh -c ordinary", null, null)', "java.shell-execution"),
    (
        'Runtime.getRuntime().exec("sh", new String[]{"-c", "ordinary"})',
        "java.runtime-exec",
    ),
    ('Runtime.getRuntime().exec(new String[]{"sh -c ordinary"})', "java.runtime-exec"),
    (
        'Runtime.getRuntime().exec(new String[]{"sh", "-c", "ordinary"})',
        "java.shell-execution",
    ),
    (
        'Runtime.getRuntime().exec(new String[]{"sh", "-c", value}, null, null)',
        "java.shell-execution",
    ),
    ("Runtime.getRuntime().exec(value)", "java.runtime-exec"),
    ('new ProcessBuilder("sh", "-c", value)', "java.shell-execution"),
    ('new ProcessBuilder("sh", value, "-c", "ordinary")', "java.process-builder"),
    ('new ProcessBuilder("sh", "-o", value, "-c", "ordinary")', "java.process-builder"),
    (
        'new ProcessBuilder(java.util.List.of("sh", "-c", "ordinary"))',
        "java.process-builder",
    ),
    (builder("/bin/bash", "-c", "ordinary"), "java.shell-execution"),
]

_CASES.extend(
    (builder("bash", *flags, "-c", "SYNTHETIC_SECRET"), "java.shell-execution")
    for flags in [
        ("-o", "pipefail"),
        ("-O", "extglob"),
        ("--rcfile", "./path with spaces"),
        ("--init-file", "./config"),
        ("+e",),
        ("+o", "errexit"),
        ("-eo", "pipefail"),
        ("--noprofile", "--norc"),
        ("-o", "pipefail", "-O", "extglob"),
    ]
)

_CASES.extend(
    (builder(*values), "java.shell-execution")
    for values in [
        ("bash", "-ec", "ordinary"),
        ("bash", "+c", "ordinary"),
        ("sh", "-o", "errexit", "-c", "ordinary"),
        ("dash", "-e", "-c", "ordinary"),
        ("zsh", "-c", "ordinary"),
        ("cmd.exe", "/C", "ordinary"),
        ("C:\\Windows\\System32\\cmd.exe", "/d", "/s", "/c", "ordinary"),
        ("cmd", "/q", "/v:off", "/c", "ordinary"),
        ("cmd", "/k", "ordinary"),
        ("powershell.exe", "-Command", "ordinary"),
        ("powershell", "-NoProfile", "-NonInteractive", "-Command", "ordinary"),
        ("pwsh", "-ExecutionPolicy", "Bypass", "-c", "ordinary"),
        ("pwsh.exe", "-NoLogo", "-Command", "ordinary"),
    ]
)

_CASES.extend(
    (builder(*values), "java.process-builder")
    for values in [
        ("bash", "--", "-c", "ordinary"),
        ("bash", "./script.sh", "-c", "ordinary"),
        ("bash", "--rcfile", "./config", "./script.sh", "-c", "ordinary"),
        ("bash", "--rcfile", "-c", "ordinary"),
        ("bash", "--unknown", "-c", "ordinary"),
        ("bash", "-Z", "-c", "ordinary"),
        ("bash", "-I", "-c", "ordinary"),
        ("bash", "--command", "ordinary"),
        ("bash", "-C", "ordinary"),
        ("sh", "-O", "extglob", "-c", "ordinary"),
        ("sh", "/c", "ordinary"),
        ("sh", "-Command", "ordinary"),
        ("cmd", "-c", "ordinary"),
        ("cmd", "-Command", "ordinary"),
        ("cmd", "/unknown", "/c", "ordinary"),
        ("cmd", "./script.cmd", "/c", "ordinary"),
        ("powershell", "/c", "ordinary"),
        ("pwsh", "-File", "./script.ps1", "-Command", "ordinary"),
        ("pwsh", "-Unknown", "-Command", "ordinary"),
        ("pwsh", "-ExecutionPolicy", "-Command", "ordinary"),
    ]
)


def source(command):
    return (
        "class Sample {\n"
        "  void launch(String value) throws Exception {\n"
        f"    {command};\n"
        "  }\n}\n"
    )


def compile_driver(compiler, root):
    """Compile only the trusted shipped observer, with empty resolution paths."""
    empty = root / "empty"
    empty.mkdir()
    asset = (
        Path(__file__).parents[1]
        / "src/diff_gremlin/analyzers/java/assets/StructureProbe.java"
    )
    built = run(
        [
            compiler,
            "-proc:none",
            "-implicit:none",
            "-classpath",
            str(empty),
            "-sourcepath",
            str(empty),
            "-d",
            str(root),
            str(asset),
        ],
        cwd=root,
        timeout=30,
    )
    assert built.status == "ok" and built.returncode == 0, built.stderr
    return root


def command_paths(root):
    """Write static target source, which is supplied only to JavacTask.parse()."""
    paths = []
    for index, (command, _) in enumerate(_CASES):
        path = root / f"Sample{index}.java"
        path.write_text(source(command), encoding="utf-8")
        paths.append(path)
    return paths


@pytest.fixture(scope="module")
def native_evidence(tmp_path_factory):
    compiler, java = shutil.which("javac"), shutil.which("java")
    if not compiler or not java:
        pytest.skip("Actual installed JDK parser required")
    root = tmp_path_factory.mktemp("java-command-probe")
    compile_driver(compiler, root)
    paths = command_paths(root)
    parsed = run(
        [java, "-cp", str(root), "StructureProbe", *(str(p) for p in paths)],
        cwd=root,
        timeout=30,
    )
    assert parsed.status == "ok" and parsed.returncode == 0, parsed.stderr
    assert "SYNTHETIC_SECRET" not in parsed.stdout + parsed.stderr
    data = json.loads(parsed.stdout)
    assert data["error_count"] == 0
    assert set(data["files"]) == {str(p) for p in paths}
    assert data["type_count"] == len(_CASES)
    assert data["method_count"] == len(_CASES)
    assert not list(root.glob("Sample*.class"))
    return {Path(f["path"]).stem: f for f in data["findings"]}


@pytest.mark.parametrize("index,case", list(enumerate(_CASES)))
def test_native_command_argument_semantics(native_evidence, index, case):
    _, rule = case
    finding = native_evidence[f"Sample{index}"]
    assert finding["rule"] == rule
    assert finding["severity"] == ("high" if rule == "java.shell-execution" else "info")
    assert (finding["line"], finding["column"]) == (3, 5)


@pytest.mark.parametrize("command,rule", _CASES[:4])
def test_execution_projection_preserves_locations_and_safe_messages(
    tmp_path, command, rule
):
    if not shutil.which("javac") or not shutil.which("java"):
        pytest.skip("Actual installed JDK parser required")
    path = tmp_path / "Sample.java"
    path.write_text(source(command), encoding="utf-8")
    file = SourceFile(path, path.name, "java", False, path.stat().st_size)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    ctx = ScanContext(tmp_path, (file,), (file,), ("java",), "full", 30, scratch, run)
    result = analyze_execution(ctx)
    assert result.status == "ok", result.reason
    assert result.analyzed_files == result.eligible_files == 1
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert (finding.path, finding.line, finding.column, finding.rule) == (
        "Sample.java",
        3,
        5,
        rule,
    )
    assert result.metrics["actionable_count"] == (rule == "java.shell-execution")
    assert "SYNTHETIC_SECRET" not in json.dumps(asdict(result))
