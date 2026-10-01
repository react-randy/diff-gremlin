"""Report named repository hygiene facts without executing project checks."""

from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_LICENSES = {"license", "licence", "copying"}
_LOCKS = {
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "Cargo.lock",
    "go.sum",
    "Gemfile.lock",
    "composer.lock",
}


def _readmes(roots):
    present, unreadable = False, []
    for name, file in roots.items():
        if name.lower().split(".")[0] != "readme":
            continue
        try:
            present |= len(file.path.read_text(encoding="utf-8").strip()) > 100
        except (OSError, UnicodeError):
            unreadable.append(name)
    return present, unreadable


def _ci_present(files, roots):
    return ".gitlab-ci.yml" in roots or any(
        name.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")) for name in files
    )


def _checks(ctx, files, roots, readme_found):
    return {
        "license_file": any(
            name.lower().split(".")[0] in _LICENSES and f.size_bytes > 0
            for name, f in roots.items()
        ),
        "nontrivial_readme": readme_found,
        "test_files": any(file.is_test and file.size_bytes > 0 for file in ctx.files),
        "gitignore_file": ".gitignore" in roots,
        "ci_configuration": _ci_present(files, roots),
        "dependency_lockfile": any(name in _LOCKS for name in roots),
    }


def analyze_hygiene(ctx: ScanContext) -> StageResult:
    files = {f.relative_path: f for f in ctx.files}
    roots = {name: file for name, file in files.items() if "/" not in name}
    readme_found, unreadable = _readmes(roots)
    checks = _checks(ctx, files, roots, readme_found)
    findings = [
        Finding(
            f"hygiene.{name}",
            f"No {name.replace('_', ' ')} found in inventoried files",
            "low",
        )
        for name, present in checks.items()
        if not present
    ]
    findings.extend(
        Finding("hygiene.unreadable", "README could not be read as UTF-8", "info", path)
        for path in unreadable
    )
    return StageResult(
        "hygiene",
        "Repository hygiene facts",
        "hygiene",
        "limited" if unreadable else "ok",
        "builtin",
        metrics={
            "checks": checks,
            "present_count": sum(checks.values()),
            "check_count": len(checks),
        },
        findings=findings,
        reason="Presence indicators only; test execution, license validity and CI behavior are unverified",
        scope="inventory",
        eligible_files=len(ctx.files),
        analyzed_files=len(ctx.files) - len(unreadable),
    )
