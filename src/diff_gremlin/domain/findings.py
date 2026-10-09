"""Located observations that readers can investigate."""

import hashlib
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
    metric: str = ""
    value: int | float | None = None
    identity_kind: Literal["observation", "qualified", "body"] = "observation"


def observation_identity(
    rule: str,
    path: str,
    symbol: str,
    message: str,
    metric: str = "",
    fingerprint: str = "",
) -> str:
    """Keep measurement value, severity and location out of persistent identity."""
    if fingerprint:
        return fingerprint
    detail = metric if metric else message
    text = f"{rule}\0{path}\0{symbol}\0{detail}"
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:20]
