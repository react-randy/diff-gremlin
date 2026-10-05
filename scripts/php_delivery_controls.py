"""Native PHP adverse controls shared by container delivery and public checks."""

import json
import subprocess
from collections.abc import Callable
from pathlib import Path

CASES = (
    ("syntax", "<?php function broken( {\n", "php.syntax.php", "ok"),
    (
        "types",
        "<?php function answer(): int { return 'wrong'; }\n",
        "php.types.phpstan",
        "ok",
    ),
    ("security", "<?php eval($_POST['code']);\n", "security.php", "ok"),
    ("clones", "<?php $answer = 42;\n", "php.duplication.jscpd", "limited"),
)


def validate_stage(stage: dict, status: str) -> None:
    """Validate the expected native observation without consuming exit semantics."""
    if stage["status"] != status:
        raise ValueError(
            f"PHP adverse control {stage['id']} has status {stage['status']}"
        )
    if status == "limited":
        if (stage["analyzed_files"], stage["eligible_files"]) != (0, 1) or not stage[
            "reason"
        ]:
            raise ValueError("PHP short clone control fabricated complete coverage")
    elif not any(
        row.get("path") == "example.php" and row.get("line") == 1
        for row in stage["findings"]
    ):
        raise ValueError(f"PHP adverse control {stage['id']} lost its located finding")


def validate_receipt(
    result: subprocess.CompletedProcess, stage_id: str, status: str
) -> dict:
    """Require actual located bad evidence, or explicit native clone omissions."""
    if result.returncode not in (1, 3):
        raise ValueError(
            f"PHP adverse control returned unexpected exit {result.returncode}"
        )
    document = json.loads(result.stdout)
    stage = next(row for row in document["stages"] if row["id"] == stage_id)
    validate_stage(stage, status)
    return {
        "stage": stage_id,
        "status": stage["status"],
        "exit_code": result.returncode,
    }


def check_cases(
    root: Path, invoke: Callable[[Path], subprocess.CompletedProcess]
) -> None:
    """Run each defect in isolation and prove scanner nonmutation."""
    for name, source, stage, status in CASES:
        (root / "example.php").write_text(source)
        before = {
            p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
        }
        receipt = validate_receipt(invoke(root), stage, status)
        after = {
            p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()
        }
        if before != after:
            raise ValueError(
                f"PHP {name} control modified source or executed target code"
            )
        print(json.dumps(receipt))
