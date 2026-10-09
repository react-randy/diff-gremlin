"""Project comparison evidence without duplicated snapshot finding arrays."""


def delta_document(document: dict) -> dict:
    base, head = document["base"], document["head"]
    return {
        "schema_version": document["schema_version"],
        "mode": "comparison-delta",
        "tool": head["tool"],
        "policy_version": head["policy_version"],
        "review": document["review"],
        "comparison_base_sha": document["comparison_base_sha"],
        "comparison_semantics": document["comparison_semantics"],
        "sources": {"base": base["source"], "head": head["source"]},
        "profiles": {"base": base["profile"], "head": head["profile"]},
        "coverage": {"base": base["coverage"], "head": head["coverage"]},
        "source_selection": {
            "base": base["source_selection"],
            "head": head["source_selection"],
        },
        "snapshot_assessments": {
            "base": base["assessment"],
            "head": head["assessment"],
        },
        "delta_assessment": document["delta_assessment"],
        "deltas": document["deltas"],
        "limitations": head["limitations"],
    }
