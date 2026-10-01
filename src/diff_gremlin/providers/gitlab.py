"""Resolve GitLab merge-request projects and captured diff revisions."""

from urllib.parse import quote

from diff_gremlin.domain.sources import ReviewTarget
from diff_gremlin.providers.metadata import (
    MetadataClient,
    nested,
    positive_id,
    required_string,
    sha,
)
from diff_gremlin.providers.urls import ReviewURL, repository_url


def _project(client: MetadataClient, project_id: int) -> dict:
    data = client.get(f"projects/{project_id}")
    if positive_id(data, "id") != project_id:
        raise RuntimeError("GitLab project response has a mismatched project identity")
    return data


def resolve_gitlab(review: ReviewURL, *, timeout: float) -> ReviewTarget:
    client = MetadataClient(review.host, "gitlab", timeout)
    data = client.get(
        f"projects/{quote(review.project, safe='')}/merge_requests/{review.request_id}"
    )
    if positive_id(data, "iid") != review.request_id:
        raise RuntimeError("GitLab response identifies a different merge request")
    target_id, source_id = (
        positive_id(data, "target_project_id"),
        positive_id(data, "source_project_id"),
    )
    target = _project(client, target_id)
    source = target if source_id == target_id else _project(client, source_id)
    target_path = required_string(target, "path_with_namespace")
    source_path = required_string(source, "path_with_namespace")
    if target_path != review.project:
        raise RuntimeError("GitLab response identifies a different target project")
    refs = nested(data, "diff_refs")
    return ReviewTarget(
        "gitlab",
        review.url,
        f"{review.host}/{target_path}",
        review.request_id,
        repository_url(target.get("http_url_to_repo"), review.host, target_path),
        repository_url(source.get("http_url_to_repo"), review.host, source_path),
        sha(refs, "start_sha"),
        sha(refs, "head_sha"),
        required_string(data, "target_branch"),
        required_string(data, "source_branch"),
        f"refs/merge-requests/{review.request_id}/head",
    )
