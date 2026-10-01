"""Resolve GitHub REST pull-request repository and immutable commit identities."""

from diff_gremlin.domain.sources import ReviewTarget
from diff_gremlin.providers.metadata import (
    MetadataClient,
    nested,
    positive_id,
    required_string,
    sha,
)
from diff_gremlin.providers.urls import ReviewURL, repository_url


def resolve_github(review: ReviewURL, *, timeout: float) -> ReviewTarget:
    client = MetadataClient(review.host, "github", timeout)
    data = client.get(f"repos/{review.project}/pulls/{review.request_id}")
    if positive_id(data, "number") != review.request_id:
        raise RuntimeError("GitHub response identifies a different pull request")
    base, head = nested(data, "base"), nested(data, "head")
    base_repo, head_repo = nested(base, "repo"), nested(head, "repo")
    base_slug = required_string(base_repo, "full_name")
    head_slug = required_string(head_repo, "full_name")
    if base_slug.lower() != review.project.lower():
        raise RuntimeError("GitHub response identifies a different target repository")
    return ReviewTarget(
        "github",
        review.url,
        f"{review.host}/{base_slug}",
        review.request_id,
        repository_url(base_repo.get("clone_url"), review.host, base_slug),
        repository_url(head_repo.get("clone_url"), review.host, head_slug),
        sha(base, "sha"),
        sha(head, "sha"),
        required_string(base, "ref"),
        required_string(head, "ref"),
        f"refs/pull/{review.request_id}/head",
    )
