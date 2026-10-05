"""First-class PHP stages, mixed PR receipts and scope boundaries."""

import json
import os
import subprocess
import sys
from dataclasses import replace

import test_polyglot

from diff_gremlin.analyzers.complexity import analyze_complexity, analyze_php_complexity
from diff_gremlin.inventory import collect_inventory
from diff_gremlin.orchestration.selection import capabilities, omitted_ids
from diff_gremlin.process import run

context = test_polyglot.context

PHP = "<?php\nclass Service {\n public function choose(bool $value): int {\n  if ($value) { return 1; }\n  return 0;\n }\n}\n"
TSX = "export function Component({enabled}: {enabled: boolean}) {\n const label = enabled ? 'yes' : 'no';\n return label;\n}\n"


def test_named_php_stages_and_quick_omissions():
    selected = capabilities(("php", "typescript"))
    ids = {stage.id for stage in selected}
    assert {
        "php.syntax.php",
        "php.types.phpstan",
        "complexity.php",
        "security.php",
        "php.duplication.jscpd",
    } <= ids
    assert "complexity.lizard" not in ids
    assert {
        "javascript.lint.eslint",
        "typescript.types.tsc",
        "security.execution",
    } <= ids
    assert "php.duplication.jscpd" in omitted_ids(selected, "quick")
    assert "security.execution" not in {stage.id for stage in capabilities(("php",))}


def test_php_inventory_tests_and_blade_are_distinct(tmp_path):
    for name in (
        "Service.php",
        "Pest.php",
        "tests/JobTest.php",
        "pages/view.blade.php",
    ):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(PHP)
    inventory = collect_inventory(tmp_path)
    files = {file.relative_path: file for file in inventory.files}
    assert files["Pest.php"].is_test and files["tests/JobTest.php"].is_test
    assert files["pages/view.blade.php"].language == "php-blade"
    assert "php.templates.blade" in {
        stage.id for stage in capabilities(inventory.languages)
    }


def test_native_php_complexity_once_and_test_exclusion(context):
    ctx = context(
        [
            ("Service.php", "php", PHP),
            (
                "tests/Pest.php",
                "php",
                '<?php it("works", function () { if (true) return 1; });\n',
            ),
        ]
    )
    ctx = replace(ctx, production_files=ctx.files[:1])
    stage = analyze_php_complexity(ctx)
    assert stage.id == "complexity.php" and stage.status == "ok", stage.reason
    assert stage.metrics["functions"] == 1 and stage.metrics["max_cc"] == 2
    assert stage.eligible_files == stage.analyzed_files == 1
    assert analyze_complexity(ctx).analyzed_files == 0


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
    ).stdout.strip()


def test_native_mixed_php_tsx_compare_attributes_both_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Service.php").write_text(PHP)
    (repo / "Component.tsx").write_text(TSX)
    (repo / "LICENSE").write_text("MIT License\n")
    (repo / "README.md").write_text(
        "# Control\nA maintained example with explicit backend and frontend review evidence.\n"
    )
    (repo / ".gitignore").write_text("vendor/\n")
    (repo / "tests").mkdir()
    (repo / "tests/Pest.php").write_text('<?php it("works", function () {});\n')
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(
        repo,
        "-c",
        "user.name=Control",
        "-c",
        "user.email=control@example.invalid",
        "commit",
        "-qm",
        "base",
    )
    base = git(repo, "rev-parse", "HEAD")
    (repo / "Service.php").write_text(PHP.replace("return 0;", 'return "bad";'))
    (repo / "Component.tsx").write_text(
        TSX.replace("const label =", "const label: number =")
    )
    git(repo, "add", ".")
    git(
        repo,
        "-c",
        "user.name=Control",
        "-c",
        "user.email=control@example.invalid",
        "commit",
        "-qm",
        "head",
    )
    head = git(repo, "rev-parse", "HEAD")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "diff_gremlin",
            "compare",
            str(repo),
            base,
            head,
            "--profile",
            "quick",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert result.returncode in (0, 3), result.stderr
    document = json.loads(result.stdout)
    stages = {stage["id"]: stage for stage in document["head"]["stages"]}
    assert (
        stages["php.syntax.php"]["analyzed_files"] == 2
    )  # Includes Pest syntax, not its complexity.
    assert stages["complexity.php"]["analyzed_files"] == 1
    assert stages["php.types.phpstan"]["findings"][0]["path"] == "Service.php"
    assert any(
        f["path"] == "Component.tsx" for f in stages["typescript.types.tsc"]["findings"]
    )
    assert "php.duplication.jscpd" in document["head"]["coverage"]["omitted_stages"]
    assert {delta["id"] for delta in document["deltas"]} >= {
        "php.types.phpstan",
        "typescript.types.tsc",
    }


def test_missing_php_tools_cannot_produce_clean_changed_php(context, monkeypatch):
    monkeypatch.setenv("DIFF_GREMLIN_TOOL_PATH", "")
    ctx = replace(context([("Service.php", "php", PHP)]), runner=run)
    results = [
        cap.analyze(ctx)
        for cap in capabilities(("php",))
        if cap.id.startswith("php.") or cap.id == "security.php"
    ]
    assert any(
        stage.id == "php.syntax.php" and stage.status == "missing" for stage in results
    )
    assert any(
        stage.id == "php.types.phpstan" and stage.status == "missing"
        for stage in results
    )
    from diff_gremlin.policy.assessment import assess

    assert assess(results).score is None and not assess(results).complete
