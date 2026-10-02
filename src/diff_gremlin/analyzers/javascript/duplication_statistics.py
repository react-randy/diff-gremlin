"""Validate native clone-incidence ratios, identities and aggregate counters."""

import hashlib
import json
import math
from collections import Counter, defaultdict

from diff_gremlin.analyzers.javascript.output import natural, positive

# getSupportedFormats() from the pinned @jscpd/tokenizer 4.2.3, sorted and
# serialized as compact JSON. Embedded maps may use any reviewed native grammar.
FORMAT_CATALOG_SHA256 = (
    "c5fd0c3849d1a1887cf2ab3e3c07c6fe22bd386b9e271973571dcc577904ab56"
)
MAX_SAFE_INTEGER = 2**53 - 1
INCIDENCE_KEYS = ("clones", "duplicatedLines", "duplicatedTokens")


def format_catalog(value: object) -> set[str]:
    """Require the exact reviewed tokenizer catalog before accepting map formats."""
    if not isinstance(value, list) or not all(isinstance(name, str) for name in value):
        raise TypeError("missing native tokenizer format catalog")
    if len(value) != 223 or len(set(value)) != len(value):
        raise ValueError("native tokenizer format catalog differs")
    canonical = json.dumps(sorted(value), separators=(",", ":")).encode()
    if hashlib.sha256(canonical).hexdigest() != FORMAT_CATALOG_SHA256:
        raise ValueError("native tokenizer format catalog differs")
    return set(value)


def percentage(value: object) -> float:
    """Incidence ratios may exceed 100 when native clone locations overlap."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError("duplication percentage must be numeric")
    try:
        ratio = float(value)
    except OverflowError as error:
        raise ValueError("invalid duplication percentage") from error
    if not math.isfinite(ratio) or ratio < 0:
        raise ValueError("invalid duplication percentage")
    return ratio


def _ratio(total: int, duplicated: int) -> float:
    """Match Statistic.calculatePercentage's positive Math.round convention."""
    return math.floor(10000.0 * duplicated / total + 0.5) / 100 if total else 0.0


def _validate_ratio(row: dict, units: str, duplicated: str, key: str) -> None:
    """An empty native denominator cannot contain positive clone incidences."""
    if row[units] == 0 and row[duplicated] > 0:
        raise ValueError("native clone incidence has a zero denominator")
    actual = percentage(row.get(key))
    expected = _ratio(row[units], row[duplicated])
    if not math.isclose(actual, expected, rel_tol=0, abs_tol=1e-9):
        raise ValueError("native duplication ratio disagrees with counters")


def statistic_row(value: object) -> dict:
    """Reject unsafe counters and percentages that disagree with native arithmetic."""
    if not isinstance(value, dict):
        raise TypeError("missing native source statistics")
    keys = ("sources", "lines", "tokens", *INCIDENCE_KEYS)
    if not all(
        natural(value.get(key)) and value[key] <= MAX_SAFE_INTEGER for key in keys
    ):
        raise ValueError("invalid native source statistics")
    for units, duplicated, key in (
        ("lines", "duplicatedLines", "percentage"),
        ("tokens", "duplicatedTokens", "percentageTokens"),
    ):
        _validate_ratio(value, units, duplicated, key)
    return value


def _format_sources(value: object, expected: set[str]) -> set[str]:
    """Verify source-map ownership and denominator totals within one grammar."""
    if not isinstance(value, dict) or not isinstance(value.get("sources"), dict):
        raise TypeError("missing per-format source identities")
    sources, total = value["sources"], statistic_row(value.get("total"))
    if total["sources"] != len(sources) or not sources.keys() <= expected:
        raise ValueError("per-format source count or identities differ")
    for row in sources.values():
        if statistic_row(row)["sources"] != 1:
            raise ValueError("invalid per-file source statistic")
    for key in ("lines", "tokens"):
        if total[key] != sum(row[key] for row in sources.values()):
            raise ValueError("per-format source units disagree with source maps")
    return set(sources)


def _clone_sources(row: dict) -> tuple[dict, tuple[str, str]]:
    """Require both source identities before accumulating clone incidences."""
    first, second = row.get("firstFile"), row.get("secondFile")
    if not isinstance(first, dict) or not isinstance(second, dict):
        raise TypeError("missing native clone locations")
    first_name, second_name = first.get("name"), second.get("name")
    if not isinstance(first_name, str) or not isinstance(second_name, str):
        raise TypeError("missing native clone source identity")
    return first, (first_name, second_name)


def _clone_units(first: dict) -> Counter:
    """Use the first location's exclusive line and token differences."""
    start, end = first.get("start"), first.get("end")
    if not positive(start) or not positive(end) or end < start:
        raise ValueError("invalid native clone line extent")
    start_point, end_point = first.get("startLoc"), first.get("endLoc")
    if not isinstance(start_point, dict) or not isinstance(end_point, dict):
        raise TypeError("missing native clone endpoints")
    begin, finish = start_point.get("position"), end_point.get("position")
    if not natural(begin) or not natural(finish) or finish < begin:
        raise ValueError("invalid native clone token extent")
    return Counter(
        clones=1, duplicatedLines=end - start, duplicatedTokens=finish - begin
    )


def _clone_incidence(row: object) -> tuple[str, tuple[str, str], Counter]:
    """Derive the native once-per-clone contribution from the first location."""
    if not isinstance(row, dict) or not isinstance(row.get("format"), str):
        raise TypeError("invalid clone format")
    first, names = _clone_sources(row)
    return row["format"], names, _clone_units(first)


def _verify_incidence(actual: dict, expected: Counter) -> None:
    """Compare only counters that the native clone callback increments."""
    if any(actual[key] != expected[key] for key in INCIDENCE_KEYS):
        raise ValueError("native clone counters disagree with clone records")


def _incidences(rows: list, formats: dict) -> tuple[Counter, dict, dict]:
    """Account for both source occurrences, including same-file clone pairs."""
    total: Counter = Counter()
    by_format: dict[str, Counter] = defaultdict(Counter)
    by_source: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for row in rows:
        name, sources, counts = _clone_incidence(row)
        if name not in formats or not set(sources) <= formats[name]["sources"].keys():
            raise ValueError("clone grammar or source outside native source maps")
        total.update(counts)
        by_format[name].update(counts)
        for source in sources:
            by_source[name, source].update(counts)
    return total, by_format, by_source


def source_ids(
    statistics: dict, expected: set[str], rows: list, catalog: set[str]
) -> set[str]:
    """Reconcile native source maps and clone incidence without changing the measure."""
    formats, total = statistics.get("formats"), statistic_row(statistics.get("total"))
    if not isinstance(formats, dict):
        raise TypeError("missing native source-map statistics")
    identities = set()
    for name, value in formats.items():
        if name not in catalog:
            raise ValueError("unexpected native duplication map format")
        identities.update(_format_sources(value, expected))
    for key in ("sources", "lines", "tokens"):
        if total[key] != sum(value["total"][key] for value in formats.values()):
            raise ValueError("native total disagrees with per-format counters")
    counts, by_format, by_source = _incidences(rows, formats)
    _verify_incidence(total, counts)
    for name, value in formats.items():
        _verify_incidence(value["total"], by_format.get(name, Counter()))
        for source, row in value["sources"].items():
            _verify_incidence(row, by_source.get((name, source), Counter()))
    return identities
