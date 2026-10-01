"""Choose a parser dialect from a bounded, owned shebang map."""

from pathlib import PurePosixPath

_DIALECTS = {"sh": "posix", "dash": "posix", "bash": "bash", "mksh": "mksh"}


def dialect(source: str) -> str:
    """Accept direct interpreters and plain env/env -S forms without options."""
    first = source.partition("\n")[0]
    if not first.startswith("#!") or len(first.encode("utf-8")) > 256:
        raise ValueError("Shell dialect unavailable: missing or oversized shebang")
    words = first[2:].split()
    if not words:
        raise ValueError("Shell dialect unavailable: empty shebang")
    interpreter = PurePosixPath(words.pop(0)).name
    if interpreter == "env":
        if words[:1] == ["-S"]:
            words.pop(0)
        interpreter = words.pop(0) if words else ""
    if words or interpreter not in _DIALECTS:
        raise ValueError("Shell dialect unsupported: interpreter or shebang arguments")
    return _DIALECTS[interpreter]
