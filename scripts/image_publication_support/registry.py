"""Authenticate registry reads and protect the canonical version tag."""

import base64
import json
import re
from pathlib import Path

from . import transport
from .policy import IMAGE, MANIFEST_TYPES, REPOSITORY, VERSION, require


def registry_token(config: Path) -> str:
    """Exchange isolated Docker login credentials for a scoped GHCR read token."""
    auth = json.loads((config / "config.json").read_text())["auths"]["ghcr.io"]["auth"]
    require(isinstance(auth, str) and bool(auth), "Missing isolated GHCR login credentials")
    try:
        base64.b64decode(auth, validate=True)
    except ValueError:
        raise ValueError("Malformed isolated GHCR login credentials") from None
    status, result = transport.http_json(
        f"https://ghcr.io/token?service=ghcr.io&scope=repository:{REPOSITORY}:pull",
        {"Authorization": f"Basic {auth}"},
    )
    require(status == 200, f"GHCR authentication failed (HTTP {status})")
    token = result.get("token")
    if not isinstance(token, str) or not token:
        raise ValueError("GHCR authentication returned no token")
    require(bool(re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token)), "Malformed GHCR read token")
    return token


def validate_absence(status: int, body: dict) -> None:
    """Only a registry's explicit authenticated missing-manifest response means absent."""
    require(status != 200, "Refusing to overwrite existing image version 1.0.0")
    require(status == 404, f"GHCR version lookup failed (HTTP {status}); absence unproven")
    errors = body.get("errors")
    if not isinstance(errors, list) or not errors:
        raise ValueError("GHCR absence response lacks errors")
    require(
        all(
            isinstance(e, dict) and e.get("code") in ("MANIFEST_UNKNOWN", "NAME_UNKNOWN")
            for e in errors
        ),
        "GHCR version lookup did not prove manifest absence",
    )


def require_absent(config: Path) -> None:
    """Prove canonical version absence immediately before index creation."""
    token = registry_token(config)
    status, body = transport.http_json(
        f"https://ghcr.io/v2/{REPOSITORY}/manifests/{VERSION}",
        {"Authorization": f"Bearer {token}", "Accept": ", ".join(MANIFEST_TYPES)},
    )
    validate_absence(status, body)
    print(f"Verified {IMAGE}:{VERSION} does not exist")
