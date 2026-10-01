"""Located observations that readers can investigate."""

from dataclasses import dataclass
from typing import Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True, slots=True)
class Finding:
    """An observation without a claim about authorship or guaranteed safety."""

    rule: str
    message: str
    severity: Severity = "medium"
    path: str = ""
    line: int = 0
    column: int = 0
    symbol: str = ""
    fingerprint: str = ""
    confidence: Literal["high", "medium", "low"] = "high"
