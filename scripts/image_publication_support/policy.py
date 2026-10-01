"""Fixed publication identity and accepted scalar identifiers."""

import re

REPOSITORY = "react-randy/diff-gremlin"
REPOSITORY_ID = 1400500531
IMAGE = f"ghcr.io/{REPOSITORY}"
TAG = "v1.0.1"
VERSION = "1.0.1"
ARCHITECTURES = ("amd64", "arm64")
MANIFEST_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)


def require(condition: bool, message: str) -> None:
    """Reject a failed publication condition with safe operation context."""
    if not condition:
        raise ValueError(message)


def sha(value: str) -> str:
    """Accept only a complete Git commit identity."""
    require(
        bool(re.fullmatch(r"[0-9a-f]{40}", value)), "Invalid source commit identity"
    )
    return value


def digest(value: str) -> str:
    """Accept only a complete SHA-256 registry digest."""
    require(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", value)), "Invalid image digest")
    return value
