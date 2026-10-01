"""Parse review URLs without using untrusted authority text in errors."""

import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class ReviewURL:
    provider: str
    host: str
    project: str
    request_id: int
    url: str


def parse_review_url(url: str) -> ReviewURL:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except (ValueError, TypeError) as exc:
        raise ValueError("Review URL has an invalid host or port") from exc
    if (
        parsed.scheme not in {"https", "http"}
        or not host
        or parsed.username
        or parsed.password
    ):
        raise ValueError(
            "Review URL must be an HTTP(S) URL without embedded credentials"
        )
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ValueError("Review URL host is invalid")
    host = host.lower() + (f":{port}" if port else "")
    github = re.fullmatch(
        r"/([^/]+)/([^/]+)/pull/([1-9][0-9]*)(?:/(files|commits|checks))?/?",
        parsed.path,
    )
    gitlab = re.fullmatch(
        r"/(.+)/-/merge_requests/([1-9][0-9]*)(?:/(diffs|commits|changes|pipelines))?/?",
        parsed.path,
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
        raise ValueError(
            "Review URL must identify a GitHub pull request or GitLab merge request"
        )
    if any(
        not re.fullmatch(r"[A-Za-z0-9_.-]+", part) or part in {".", ".."}
        for part in project.split("/")
    ):
        raise ValueError("Review URL project path is invalid")
    return ReviewURL(provider, host, project, number, f"{parsed.scheme}://{host}{path}")


def repository_url(url: object, host: str, project: str | None = None) -> str:
    if not isinstance(url, str):
        raise RuntimeError("Provider metadata lacks a repository URL")  # noqa: TRY004
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != host
        or parsed.username
        or parsed.password
    ):
        raise RuntimeError(
            "Provider repository URL does not match the requested HTTPS host"
        )
    if parsed.query or parsed.fragment:
        raise RuntimeError("Provider repository URL contains unexpected URL parameters")
    slug = parsed.path.strip("/").removesuffix(".git")
    if project is not None and slug.lower() != project.lower():
        raise RuntimeError(
            "Provider repository identity does not match the requested project"
        )
    if not slug or any(
        not re.fullmatch(r"[A-Za-z0-9_.-]+", part) or part in {".", ".."}
        for part in slug.split("/")
    ):
        raise RuntimeError("Provider repository project path is invalid")
    return f"https://{host}/{slug}.git"
