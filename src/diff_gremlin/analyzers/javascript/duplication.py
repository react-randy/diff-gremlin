"""Read only fresh jscpd evidence from an invocation-owned source view."""

import json
import math
import tempfile
from pathlib import Path

from diff_gremlin.analyzers.status import unavailable

from diff_gremlin.analyzers.javascript.installed import (
    installed_package,
    package_version,
    trusted_executable,
)
from diff_gremlin.analyzers.javascript.output import natural
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_ID, _LABEL = "javascript.duplication.jscpd", "JavaScript/TypeScript duplication"


def _report(
    report_path: Path, source: Path, eligible: int
) -> tuple[float, list[Finding], int]:
    data = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("statistics"), dict):
        raise TypeError("missing duplication statistics")
    total = data["statistics"].get("total")
    clones = data.get("duplicates")
    if not isinstance(total, dict) or not isinstance(clones, list):
        raise TypeError("missing total statistics or clone list")
    percentage, sources = total.get("percentage"), total.get("sources")
    if (
        not isinstance(percentage, (int, float))
        or isinstance(percentage, bool)
        or not math.isfinite(percentage)
        or not 0 <= percentage <= 100
    ):
        raise ValueError("invalid duplication percentage")
    if not natural(sources) or not 0 < sources <= eligible:
        raise ValueError("invalid analyzed file count")
    if not natural(total.get("clones")) or total["clones"] != len(clones):
        raise ValueError("clone count differs from records")
    findings = []
    for clone in clones:
        if not isinstance(clone, dict) or not natural(clone.get("lines")):
            raise ValueError("invalid clone record")
        for side in ("firstFile", "secondFile"):
            location = clone.get(side)
            if not isinstance(location, dict) or not isinstance(
                location.get("name"), str
            ):
                raise TypeError("invalid clone location")
            path = Path(location["name"])
            path = path if path.is_absolute() else source / path
            relative = path.resolve().relative_to(source.resolve())
            if (
                not path.is_file()
                or not natural(location.get("start"))
                or location["start"] < 1
            ):
                raise ValueError("clone location outside analyzed files")
            findings.append(
                Finding(
                    "duplication.clone",
                    "Duplicated block; review both clone locations",
                    "low",
                    str(relative),
                    location["start"],
                    1,
                )
            )
    return float(percentage), findings, sources


def analyze_js_duplication(ctx: ScanContext) -> StageResult:
    files = tuple(
        file
        for file in ctx.production_files
        if file.language in {"javascript", "typescript"}
    )

    def absent(reason, status="missing"):
        return unavailable(
            _ID,
            _LABEL,
            "duplication",
            "jscpd",
            reason,
            status=status,
            eligible_files=len(files),
        )

    if not files:
        return absent("No JavaScript or TypeScript production files", "skipped")
    package = installed_package(ctx, "jscpd", "jscpd")
    binary = trusted_executable(ctx, "jscpd")
    node = trusted_executable(ctx, "node")
    if not package or not binary or not node:
        return absent("Installed trusted Node/jscpd package unavailable")
    with tempfile.TemporaryDirectory(prefix="jscpd-", dir=ctx.scratch) as directory:
        workspace = Path(directory)
        source = workspace / "source"
        source.mkdir()
        try:
            for file in files:
                destination = source / file.relative_path
                if not destination.resolve().is_relative_to(source.resolve()):
                    raise ValueError("source inventory path escapes workspace")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(file.path.read_bytes())
            config = workspace / "config.json"
            config.write_text("{}", encoding="utf-8")
            output = workspace / "output"
            result = ctx.run(
                [
                    node,
                    binary,
                    str(source),
                    "--config",
                    str(config),
                    "--reporters",
                    "json",
                    "--output",
                    str(output),
                    "--format",
                    "javascript,typescript,jsx,tsx",
                    "--silent",
                    "--absolute",
                    "--noSymlinks",
                    "--noTips",
                ],
                cwd=workspace,
            )
            if result.status != "ok" or result.returncode != 0:
                return absent(
                    f"Controlled jscpd invocation {result.status}; exit {result.returncode}",
                    result.status
                    if result.status in {"missing", "timeout"}
                    else "failed",
                )
            percentage, findings, count = _report(
                output / "jscpd-report.json", source, len(files)
            )
        except (OSError, ValueError, TypeError):
            return absent(
                "jscpd report missing, unreadable, or schema/coverage invalid for this invocation",
                "failed",
            )
    return StageResult(
        _ID,
        _LABEL,
        "duplication",
        "ok" if count == len(files) else "limited",
        "jscpd",
        package_version(package),
        metrics={"duplication_percent": percentage, "clone_groups": len(findings) // 2},
        findings=findings,
        reason=""
        if count == len(files)
        else "jscpd analyzed fewer files than the selected inventory",
        eligible_files=len(files),
        analyzed_files=count,
        duration_seconds=result.duration_seconds,
    )
