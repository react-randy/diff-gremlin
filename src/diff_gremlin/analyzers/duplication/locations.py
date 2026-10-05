"""Validate native clone locations against copied source coordinates."""

from pathlib import Path

from diff_gremlin.analyzers.javascript.output import natural, positive
from diff_gremlin.domain.findings import Finding

_MAX_SOURCE_BYTES = 100 * 1024


class CloneCoordinateError(ValueError):
    """A well-formed native clone location disagrees with captured source."""


def _source_lengths(name: str) -> tuple[int, ...]:
    with Path(name).open("rb") as stream:
        contents = stream.read(_MAX_SOURCE_BYTES + 1)
    if len(contents) > _MAX_SOURCE_BYTES:
        raise ValueError("clone source exceeds native file size limit")
    # Native tokenizer columns count UTF-16 units; only LF advances its line counter.
    lines = contents.decode("utf-8", errors="replace").split("\n")
    return tuple(len(line.encode("utf-16-le")) // 2 for line in lines)


def _clone_point(point: object, line: int) -> dict:
    if (
        not isinstance(point, dict)
        or not positive(point.get("line"))
        or point.get("line") != line
    ):
        raise ValueError("clone endpoint differs from reported line")
    if not positive(point.get("column")) or not natural(point.get("position")):
        raise ValueError("invalid clone endpoint")
    return point


def _clone_schema(location: object, paths: dict[str, str]) -> dict:
    """Malformed or foreign records never become recognized native defects."""
    if not isinstance(location, dict) or not isinstance(location.get("name"), str):
        raise TypeError("invalid clone location")
    if location["name"] not in paths:
        raise ValueError("clone location outside analyzed files")
    start, end = location.get("start"), location.get("end")
    if not positive(start) or not positive(end):
        raise ValueError("invalid clone line extent")
    _clone_point(location.get("startLoc"), start)
    _clone_point(location.get("endLoc"), end)
    return location


def _clone_range(location: dict, lengths: tuple[int, ...]) -> None:
    start, end = location["start"], location["end"]
    if not 1 <= start <= end <= len(lengths):
        raise CloneCoordinateError("clone range outside source lines")
    first, last = location["startLoc"], location["endLoc"]
    if any(point["column"] > lengths[point["line"] - 1] + 1 for point in (first, last)):
        raise CloneCoordinateError("clone column outside source line")
    if (start, first["column"]) > (end, last["column"]):
        raise CloneCoordinateError("reversed clone endpoints")
    if first["position"] > last["position"]:
        raise CloneCoordinateError("reversed native clone positions")


def _clone_location(
    location: object, paths: dict[str, str], lengths: dict[str, tuple[int, ...]]
) -> Finding:
    location = _clone_schema(location, paths)
    name = location["name"]
    _clone_range(location, lengths[name])
    return Finding(
        "duplication.clone",
        "Duplicated block; review both clone locations",
        "low",
        paths[name],
        location["start"],
        1,
    )


def _clones(rows: list, paths: dict[str, str]) -> tuple[list[Finding], dict[str, int]]:
    findings, rejected = [], {}
    lengths = {name: _source_lengths(name) for name in paths} if rows else {}
    for row in rows:
        if not isinstance(row, dict) or not positive(row.get("lines")):
            raise ValueError("invalid clone record")
        first = _clone_schema(row.get("firstFile"), paths)
        second = _clone_schema(row.get("secondFile"), paths)
        if row["lines"] != first["end"] - first["start"] + 1:
            raise ValueError("clone extent differs from first source range")
        # RabinKarp.enlargeClone may replace B.end using a different hash-hit source.
        # A remains the scanned source: only well-formed B coordinate defects degrade.
        first_finding = _clone_location(first, paths, lengths)
        try:
            second_finding = _clone_location(second, paths, lengths)
        except CloneCoordinateError as error:
            cause = str(error)
            rejected[cause] = rejected.get(cause, 0) + 1
            continue
        findings.extend((first_finding, second_finding))
    return findings, rejected
