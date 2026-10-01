"""Reject unsupported Python analyzer JSON value shapes."""

import json
import math
from typing import Any


def object_value(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("expected JSON object")
    return value


def list_value(value: object) -> list[Any]:
    if not isinstance(value, list):
        raise TypeError("expected JSON list")
    return value


def count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError("expected nonnegative integer")
    return value


def number(value: object, *, minimum: float = 0, maximum: float = 100) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("expected finite number")
    if not minimum <= value <= maximum:
        raise ValueError("number outside allowed range")
    return float(value)


def json_value(text: str) -> object:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid JSON output") from exc
