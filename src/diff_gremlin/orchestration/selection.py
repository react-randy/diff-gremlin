"""The declared profile determines selected and deliberately omitted stages."""

from collections.abc import Callable
from dataclasses import dataclass

from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import Category, StageResult


@dataclass(frozen=True, slots=True)
class Capability:
    id: str
    label: str
    category: Category
    analyze: Callable[[ScanContext], StageResult | list[StageResult]]
    full_only: bool = False


def python_capabilities() -> list[Capability]:
    from diff_gremlin.analyzers.python.maintainability import analyze_maintainability
    from diff_gremlin.analyzers.python.pyscn import analyze_pyscn
    from diff_gremlin.analyzers.python.ruff import analyze_ruff
    from diff_gremlin.analyzers.python.types import analyze_python_types

    return [
        Capability("python.lint.ruff", "Python lint", "lint", analyze_ruff),
        Capability("python.types.pyrefly", "Python types", "types", analyze_python_types),
        Capability(
            "python.health.pyscn",
            "Python health, clones and dead code",
            "health",
            analyze_pyscn,
            True,
        ),
        Capability(
            "python.maintainability.radon",
            "Maintainability",
            "maintainability",
            analyze_maintainability,
            True,
        ),
    ]


def javascript_capabilities(languages: tuple[str, ...]) -> list[Capability]:
    from diff_gremlin.analyzers.javascript.complexity import analyze_js_complexity
    from diff_gremlin.analyzers.javascript.duplication import analyze_js_duplication
    from diff_gremlin.analyzers.javascript.lint import analyze_js_lint
    from diff_gremlin.analyzers.javascript.types import analyze_ts_types

    result = [
        Capability(
            "complexity.javascript",
            "JavaScript/TypeScript function complexity",
            "complexity",
            analyze_js_complexity,
        ),
        Capability("javascript.lint.eslint", "JavaScript/TypeScript lint", "lint", analyze_js_lint),
        Capability(
            "javascript.duplication.jscpd",
            "JavaScript/TypeScript clones",
            "duplication",
            analyze_js_duplication,
            True,
        ),
    ]
    if "typescript" in languages:
        result.append(
            Capability("typescript.types.tsc", "TypeScript types", "types", analyze_ts_types)
        )
    return result


def java_capabilities() -> list[Capability]:
    from diff_gremlin.analyzers.java.structure import analyze_java_structure
    from diff_gremlin.analyzers.java.types import analyze_java_types

    return [
        Capability("java.structure", "Java parser structure", "structure", analyze_java_structure),
        Capability("java.types", "Standalone Java types", "types", analyze_java_types),
    ]


def builtin_capabilities() -> list[Capability]:
    from diff_gremlin.analyzers.execution import analyze_execution
    from diff_gremlin.analyzers.hygiene import analyze_hygiene
    from diff_gremlin.analyzers.secrets import analyze_secrets
    from diff_gremlin.analyzers.unicode import analyze_unicode

    return [
        Capability("hygiene", "Repository hygiene", "hygiene", analyze_hygiene),
        Capability("security.unicode", "Unicode controls", "security", analyze_unicode),
        Capability("security.execution", "Execution calls", "security", analyze_execution),
        Capability("security.secrets", "Potential secrets", "security", analyze_secrets),
    ]


def capabilities(languages: tuple[str, ...]) -> list[Capability]:
    from diff_gremlin.analyzers.complexity import analyze_complexity

    result = builtin_capabilities()
    if set(languages) - {"javascript", "typescript", "shell"}:
        result.append(
            Capability("complexity.lizard", "Function complexity", "complexity", analyze_complexity)
        )
    if "python" in languages:
        result.extend(python_capabilities())
    if set(languages) & {"javascript", "typescript"}:
        result.extend(javascript_capabilities(languages))
    if "java" in languages:
        result.extend(java_capabilities())
    return result


def omitted_ids(selected: list[Capability], profile: str) -> tuple[str, ...]:
    if profile == "full":
        return ()
    omitted = [cap.id for cap in selected if cap.full_only]
    if "python.health.pyscn" in omitted:
        omitted.extend(("python.duplication.pyscn", "python.deadcode.pyscn"))
    return (*omitted, "history.git")
