"""Bind native image receipts to a source and verify the resulting index."""

import json
from pathlib import Path

from .policy import ARCHITECTURES, IMAGE, MANIFEST_TYPES, VERSION, digest, require, sha


def receipt_identity(architecture: str, source: str, run_id: str, attempt: str) -> dict:
    """Bind a successful native build receipt to its source and workflow attempt."""
    require(architecture in ARCHITECTURES, "Unsupported native image architecture")
    require(run_id.isdigit() and attempt.isdigit(), "Invalid workflow run identity")
    return {
        "architecture": architecture,
        "source": sha(source),
        "image": IMAGE,
        "version": VERSION,
        "run_id": run_id,
        "attempt": attempt,
    }


def pushed_receipt(
    architecture: str,
    source: str,
    run_id: str,
    attempt: str,
    platform: str,
    references: list,
) -> dict:
    """Validate one native build's platform and successfully pushed digest."""
    receipt = receipt_identity(architecture, source, run_id, attempt)
    require(platform == f"linux/{architecture}", "Built image platform mismatch")
    require(
        isinstance(references, list) and len(references) == 1, "Ambiguous pushed digest"
    )
    reference = references[0]
    require(
        isinstance(reference, str) and reference.startswith(f"{IMAGE}@"),
        "Pushed digest names an unexpected image",
    )
    receipt["digest"] = digest(reference.removeprefix(f"{IMAGE}@"))
    return receipt


def write_receipt(output: Path, receipt: dict) -> None:
    """Serialize a validated native receipt for the current workflow artifact."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, sort_keys=True) + "\n")


def read_receipts(
    directory: Path, source: str, run_id: str, attempt: str
) -> dict[str, str]:
    """Require exactly one current-attempt receipt for each required architecture."""
    paths = sorted(directory.glob("*/*.json"))
    require(len(paths) == 2, "Expected exactly two native image receipts")
    result = {}
    for path in paths:
        receipt = json.loads(path.read_text())
        architecture = receipt.get("architecture")
        expected = receipt_identity(architecture, source, run_id, attempt)
        require(
            set(receipt) == {*expected, "digest"}, "Unexpected native receipt fields"
        )
        require(
            all(receipt[k] == v for k, v in expected.items()),
            "Receipt identity mismatch",
        )
        require(architecture not in result, "Duplicate native architecture receipt")
        result[architecture] = digest(receipt["digest"])
    require(
        set(result) == set(ARCHITECTURES), "Incomplete native architecture receipts"
    )
    return result


def validate_index(manifest: dict, receipts: dict[str, str]) -> None:
    """Require the published version index to contain only the two verified images."""
    require(
        manifest.get("mediaType") in MANIFEST_TYPES[:2],
        "Published image is not an index",
    )
    descriptors = manifest.get("manifests", [])
    require(len(descriptors) == 2, "Published index must contain exactly two images")
    actual = {}
    for descriptor in descriptors:
        platform = descriptor.get("platform", {})
        require(
            platform.get("os") == "linux", "Published index contains a non-Linux image"
        )
        architecture = platform.get("architecture")
        require(architecture not in actual, "Published index repeats an architecture")
        actual[architecture] = digest(descriptor["digest"])
    require(
        actual == receipts, "Published index does not match validated native receipts"
    )
