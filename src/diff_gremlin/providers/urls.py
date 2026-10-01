"""Parse review URLs without using untrusted authority text in errors."""

import re
from dataclasses import dataclass

from diff_gremlin.providers.url_validation import (
    repository_location,
    review_authority,
    valid_project,
)


@dataclass(frozen=True, slots=True)
class ReviewURL:
    provider: str
    host: str
    project: str
    request_id: int
    url: str


def _review_path(path: str) -> tuple[str, str, int, str]:
    github = re.fullmatch(
        r"/([^/]+)/([^/]+)/pull/([1-9][0-9]*)(?:/(files|commits|checks))?/?",
        path,
    )
    gitlab = re.fullmatch(
        r"/(.+)/-/merge_requests/([1-9][0-9]*)(?:/(diffs|commits|changes|pipelines))?/?",
        path,
    )
    if github:
        project = f"{github[1]}/{github[2]}"
        number, provider = int(github[3]), "github"
        path = f"/{project}/pull/{number}"
    elif gitlab:
        project = gitlab[1]
        number, provider = int(gitlab[2]), "gitlab"
        path = f"/{project}/-/merge_requests/{number}"
    else:
        raise ValueError("Review URL must identify a GitHub pull request or GitLab merge request")
    return provider, project, number, path


def parse_review_url(url: str) -> ReviewURL:
    parsed, host = review_authority(url)
    provider, project, number, path = _review_path(parsed.path)
    if not valid_project(project):
        raise ValueError("Review URL project path is invalid")
    return ReviewURL(provider, host, project, number, f"{parsed.scheme}://{host}{path}")


def repository_url(url: object, host: str, project: str | None = None) -> str:
    parsed = repository_location(url, host)
    slug = parsed.path.strip("/").removesuffix(".git")
    if project is not None and slug.lower() != project.lower():
        raise RuntimeError("Provider repository identity does not match the requested project")
    if not valid_project(slug):
        raise RuntimeError("Provider repository project path is invalid")
    return f"https://{host}/{slug}.git"
