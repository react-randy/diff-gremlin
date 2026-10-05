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
        Capability(
            "python.types.pyrefly", "Python types", "types", analyze_python_types
        ),
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
        Capability(
            "javascript.lint.eslint",
            "JavaScript/TypeScript lint",
            "lint",
            analyze_js_lint,
        ),
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
            Capability(
                "typescript.types.tsc", "TypeScript types", "types", analyze_ts_types
            )
        )
    return result


def java_capabilities() -> list[Capability]:
    from diff_gremlin.analyzers.java.structure import analyze_java_structure
    from diff_gremlin.analyzers.java.types import analyze_java_types

    return [
        Capability(
            "java.structure",
            "Java parser structure",
            "structure",
            analyze_java_structure,
        ),
        Capability("java.types", "Standalone Java types", "types", analyze_java_types),
    ]


def shell_capabilities() -> list[Capability]:
    from diff_gremlin.analyzers.shell import (
        analyze_shell_complexity,
        analyze_shell_syntax,
    )

    return [
        Capability(
            "shell.syntax.shfmt", "Shell syntax", "structure", analyze_shell_syntax
        ),
        Capability(
            "complexity.shell",
            "Shell function decisions",
            "complexity",
            analyze_shell_complexity,
        ),
    ]


def builtin_capabilities() -> list[Capability]:
    from diff_gremlin.analyzers.execution import analyze_execution
    from diff_gremlin.analyzers.hygiene import analyze_hygiene
    from diff_gremlin.analyzers.secrets import analyze_secrets
    from diff_gremlin.analyzers.unicode import analyze_unicode

    return [
        Capability("hygiene", "Repository hygiene", "hygiene", analyze_hygiene),
        Capability("security.unicode", "Unicode controls", "security", analyze_unicode),
        Capability(
            "security.execution", "Execution calls", "security", analyze_execution
        ),
        Capability(
            "security.secrets", "Potential secrets", "security", analyze_secrets
        ),
    ]


def php_capabilities() -> list[Capability]:
    from diff_gremlin.analyzers.complexity import analyze_php_complexity
    from diff_gremlin.analyzers.php.duplication import analyze_php_duplication
    from diff_gremlin.analyzers.php.security import analyze_php_security
    from diff_gremlin.analyzers.php.syntax import analyze_php_syntax
    from diff_gremlin.analyzers.php.types import analyze_php_types

    return [
        Capability("php.syntax.php", "PHP syntax", "structure", analyze_php_syntax),
        Capability(
            "php.types.phpstan", "PHP snapshot types", "types", analyze_php_types
        ),
        Capability(
            "complexity.php",
            "PHP function complexity",
            "complexity",
            analyze_php_complexity,
        ),
        Capability(
            "security.php",
            "PHP security observations",
            "security",
            analyze_php_security,
        ),
        Capability(
            "php.duplication.jscpd",
            "PHP clones",
            "duplication",
            analyze_php_duplication,
            True,
        ),
    ]


def blade_capabilities() -> list[Capability]:
    from diff_gremlin.analyzers.php.scope import analyze_blade_scope

    return [
        Capability(
            "php.templates.blade",
            "Blade template coverage",
            "structure",
            analyze_blade_scope,
        )
    ]


def capabilities(languages: tuple[str, ...]) -> list[Capability]:
    from diff_gremlin.analyzers.complexity import analyze_complexity

    observed = set(languages)
    result = builtin_capabilities()
    if observed and not observed - {"php", "php-blade"}:
        result = [cap for cap in result if cap.id != "security.execution"]
    if observed - {"javascript", "typescript", "shell", "php", "php-blade"}:
        result.append(
            Capability(
                "complexity.lizard",
                "Function complexity",
                "complexity",
                analyze_complexity,
            )
        )
    builders = (
        ({"python"}, python_capabilities),
        ({"javascript", "typescript"}, lambda: javascript_capabilities(languages)),
        ({"java"}, java_capabilities),
        ({"shell"}, shell_capabilities),
        ({"php"}, php_capabilities),
        ({"php-blade"}, blade_capabilities),
    )
    for supported, build in builders:
        if observed & supported:
            result.extend(build())
    return result


def omitted_ids(selected: list[Capability], profile: str) -> tuple[str, ...]:
    if profile == "full":
        return ()
    omitted = [cap.id for cap in selected if cap.full_only]
    if "python.health.pyscn" in omitted:
        omitted.extend(("python.duplication.pyscn", "python.deadcode.pyscn"))
    return (*omitted, "history.git")
