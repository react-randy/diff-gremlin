"""Versioned, complete JSON receipts."""

import json
from dataclasses import asdict

from diff_gremlin import __version__
from diff_gremlin.domain.reports import ScanReport
from diff_gremlin.policy.metrics import stage_score
from diff_gremlin.policy.thresholds import POLICY_VERSION
from diff_gremlin.reporting.advice import next_actions

SCHEMA_VERSION = "1.1.0"


def stage_document(stage):
    result = asdict(stage)
    result["score"] = stage_score(stage)
    return result


def report_document(report: ScanReport) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "diff-gremlin", "version": __version__},
        "policy_version": POLICY_VERSION,
        "source": asdict(report.source),
        "profile": report.profile,
        "languages": list(report.languages),
        "assessment": asdict(report.assessment),
        "coverage": {
            "required_stages": report.assessment.required_stages,
            "completed_stages": report.assessment.completed_stages,
            "omitted_stages": list(report.omitted_stages),
            "scope": "production static evidence; security and hygiene inspect inventoried text",
        },
        "stages": [stage_document(stage) for stage in report.stages],
        "next_actions": next_actions(report),
        "duration_seconds": round(report.duration_seconds, 3),
        "limitations": [
            "Static checks do not certify security, correctness, or authorship.",
            "Target builds, tests, plugins and dependency installation are never run.",
        ],
    }


def json_text(document: dict) -> str:
    return json.dumps(document, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
