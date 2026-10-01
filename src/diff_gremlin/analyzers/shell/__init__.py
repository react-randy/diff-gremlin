"""Bounded static Shell syntax, decision estimates and command observations."""

from diff_gremlin.analyzers.shell.stages import (
    analyze_shell_complexity,
    analyze_shell_syntax,
    shell_observations,
)

__all__ = ["analyze_shell_complexity", "analyze_shell_syntax", "shell_observations"]
