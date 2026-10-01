"""Validate bounded provider JSON responses and immutable object identities."""

import json
import re
import time

from diff_gremlin.process import run
from diff_gremlin.providers.auth import provider_environment


def object_payload(text: str) -> dict:
    try:
        value = json.loads(text)
    except (ValueError, TypeError) as exc:
        raise RuntimeError("Provider returned malformed JSON metadata") from exc
    if not isinstance(value, dict) or not value:
        raise RuntimeError("Provider returned incomplete object metadata")
    return value


def required_string(data: dict, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"Provider metadata lacks a valid {key} field")
    return value


def sha(data: dict, key: str) -> str:
    value = required_string(data, key)
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        raise RuntimeError(f"Provider metadata lacks a full {key} object ID")
    return value.lower()


def positive_id(data: dict, key: str) -> int:
    value = data.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RuntimeError(f"Provider metadata lacks a valid {key} identity")
    return value


def nested(data: dict, key: str) -> dict:
    value = data.get(key)
    if not isinstance(value, dict) or not value:
        raise RuntimeError(f"Provider metadata lacks a valid {key} object")
    return value


class MetadataClient:
    """Apply one deadline to all requests needed to resolve a review."""

    def __init__(self, host: str, provider: str, timeout: float):
        self.host = host
        self.provider = provider
        self.deadline = time.monotonic() + timeout

    def get(self, endpoint: str) -> dict:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Provider metadata resolution timed out")
        cli = "gh" if self.provider == "github" else "glab"
        command = [cli, "api", "--hostname", self.host, "--method", "GET", endpoint]
        result = run(
            command,
            timeout=remaining,
            env=provider_environment(self.host, self.provider),
        )
        if result.status != "ok" or result.returncode != 0:
            # CLI diagnostics can contain credentials unknown to our process; do not echo them.
            raise RuntimeError(
                f"{self.provider} metadata request failed ({result.status}); check host authentication and access"
            )
        return object_payload(result.stdout)
