"""Resolve trusted installed executables and isolate child configuration."""

import os
import re
import shutil
import sys
from collections.abc import Mapping
from pathlib import Path

_SECRET_KEY = re.compile(
    r"token|password|secret|credential|authorization|api[_-]?key", re.IGNORECASE
)


def redact(text: str, env: Mapping[str, str] | None = None) -> str:
    """Remove credential values and URL user information from diagnostic text."""
    for source in (os.environ, env or {}):
        for key, value in source.items():
            if value and _SECRET_KEY.search(key):
                text = text.replace(value, "[redacted]")
    return re.sub(r"(https?://)[^/\s@]+@", r"\1[redacted]@", text)


def trusted_path(cwd: Path | None = None) -> str:
    """Exclude relative search paths and executable directories inside the target."""
    root = cwd.resolve() if cwd else None
    candidates = [str(Path(sys.executable).parent), *os.defpath.split(os.pathsep)]
    candidates.extend(os.environ.get("DIFF_GREMLIN_TOOL_PATH", "").split(os.pathsep))
    paths = []
    for entry in candidates:
        directory = Path(entry)
        if not entry or not directory.is_absolute():
            continue
        resolved = directory.resolve()
        if root and (resolved == root or root in resolved.parents):
            continue
        if str(resolved) not in paths:
            paths.append(str(resolved))
    return os.pathsep.join(paths)


def minimal_environment(home: Path, cwd: Path | None = None) -> dict[str, str]:
    """Keep tool configuration and credentials outside the analyzer environment."""
    return {
        "PATH": trusted_path(cwd),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_CACHE_HOME": str(home / "cache"),
        "TMPDIR": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "NO_COLOR": "1",
        "CI": "true",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }


def _executable(name: str, cwd: Path | None, path: str) -> str | None:
    candidate = Path(name)
    if candidate.is_absolute():
        resolved = candidate.resolve()
        lexical = candidate.absolute()
        if cwd and any(
            path == cwd.resolve() or cwd.resolve() in path.parents for path in (resolved, lexical)
        ):
            return None
        return str(resolved)
    if candidate.name != name:
        return None
    executable = shutil.which(name, path=path)
    if executable and cwd and cwd.resolve() in Path(executable).resolve().parents:
        return None
    return executable
