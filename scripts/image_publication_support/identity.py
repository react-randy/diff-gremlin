"""Verify the owned repository, published release and immutable source."""

import json
import os
from pathlib import Path

from . import transport
from .policy import REPOSITORY, REPOSITORY_ID, TAG, VERSION, require, sha


def github_metadata(endpoint: str) -> dict:
    """Read this public repository's live metadata without a secret."""
    status, result = transport.http_json(
        f"https://api.github.com/repos/{REPOSITORY}/{endpoint}".rstrip("/"),
        {
            "Accept": "application/vnd.github+json",
            "User-Agent": "diff-gremlin-publication",
        },
    )
    require(status == 200, f"GitHub publication identity lookup failed (HTTP {status})")
    return result


def validate_repository(context: dict, repository: dict) -> None:
    """Require the authorized public repository and its main branch."""
    require(
        context["GITHUB_REPOSITORY"] == REPOSITORY, "Unexpected workflow repository"
    )
    require(
        context["GITHUB_REPOSITORY_ID"] == str(REPOSITORY_ID),
        "Unexpected repository ID",
    )
    require(
        repository.get("full_name") == REPOSITORY, "Repository lookup identity mismatch"
    )
    require(repository.get("id") == REPOSITORY_ID, "Repository lookup ID mismatch")
    require(
        repository.get("private") is False, "Publication requires the owned public repo"
    )
    require(repository.get("default_branch") == "main", "Unexpected default branch")


def validate_release(release: dict) -> None:
    """Require the fixed published stable release."""
    require(release.get("tag_name") == TAG, "Unexpected release tag")
    require(release.get("draft") is False, "Draft release cannot publish an image")
    require(release.get("prerelease") is False, "Prerelease cannot publish an image")
    require(bool(release.get("published_at")), "Release has not been published")
    require(type(release.get("id")) is int, "Missing stable release identity")


def validate_event(context: dict, event: dict, release: dict) -> None:
    """Accept dispatch from main or the exact published-release event."""
    event_name = context["GITHUB_EVENT_NAME"]
    if event_name == "workflow_dispatch":
        require(
            context["GITHUB_REF"] == "refs/heads/main", "Dispatch must run from main"
        )
        require(event.get("inputs", {}).get("tag") == TAG, "Dispatch must name v1.0.3")
        return
    require(event_name == "release", "Unsupported publication event")
    require(event.get("action") == "published", "Release event must be published")
    require(context["GITHUB_REF"] == f"refs/tags/{TAG}", "Release ref mismatch")
    event_release = event.get("release", {})
    validate_release(event_release)
    require(event_release["id"] == release["id"], "Release event identity has changed")


def validate_source(
    context: dict, tag_sha: str, main_sha: str, expected: str | None
) -> str:
    """Require immutable checkout, release tag and current main to agree."""
    source = sha(tag_sha)
    require(source == sha(main_sha), "Release tag does not match current main")
    require(
        source == sha(context["GITHUB_SHA"]), "Workflow checkout does not match release"
    )
    if expected is not None:
        require(
            source == sha(expected),
            "Publication source changed after the identity gate",
        )
    return source


def guard(expected: str | None, release_id: str | None = None) -> None:
    """Resolve and recheck live release identity before each publication transition."""
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    repository = github_metadata("")
    release = github_metadata(f"releases/tags/{TAG}")
    validate_repository(dict(os.environ), repository)
    validate_release(release)
    if release_id is not None:
        require(
            str(release["id"]) == release_id,
            "Published release identity changed during run",
        )
    validate_event(dict(os.environ), event, release)
    source = validate_source(
        dict(os.environ),
        github_metadata(f"commits/{TAG}")["sha"],
        github_metadata("commits/main")["sha"],
        expected,
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"sha={source}\nversion={VERSION}\nrelease_id={release['id']}\n")
    print(f"Verified {REPOSITORY} release {TAG} at {source}")
