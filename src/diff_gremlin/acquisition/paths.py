"""Validate filesystem paths contained by an owned source snapshot."""

from pathlib import PurePosixPath


def safe_path(path: str) -> PurePosixPath:
    value = PurePosixPath(path)
    if (
        value.is_absolute()
        or any(part in {"..", ".git"} for part in value.parts)
        or not value.parts
    ):
        raise RuntimeError("Source tree contains an unsafe path")
    return value


def safe_link(path: str, target: str) -> None:
    if not target or PurePosixPath(target).is_absolute():
        raise RuntimeError("Source symbolic link escapes its snapshot")
    parts = list(PurePosixPath(path).parent.parts)
    for part in PurePosixPath(target).parts:
        if part == "..":
            if not parts:
                raise RuntimeError("Source symbolic link escapes its snapshot")
            parts.pop()
        elif part != ".":
            parts.append(part)
