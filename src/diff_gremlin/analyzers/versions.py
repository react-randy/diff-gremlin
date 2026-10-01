"""Extract installed tool identity in the controlled scratch directory."""

import re

from diff_gremlin.domain.context import ScanContext

_VERSION = re.compile(r"\b\d+(?:\.\d+)+(?:[-+][A-Za-z0-9.]+)?\b")


def tool_version(ctx: ScanContext, executable: str) -> str:
    """Return a version token, never untrusted repository output or a grade."""
    result = ctx.run([executable, "--version"], cwd=ctx.scratch, timeout=10)
    if result.status != "ok" or result.returncode != 0:
        return ""
    match = _VERSION.search(result.stdout or result.stderr)
    return match.group(0) if match else ""
