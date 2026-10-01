"""Validate provider URL authorities and project path segments."""

import re
from urllib.parse import SplitResult, urlsplit


def valid_project(project: str) -> bool:
    return bool(project) and all(
        re.fullmatch(r"[A-Za-z0-9_.-]+", part) and part not in {".", ".."}
        for part in project.split("/")
    )


def review_authority(url: str) -> tuple[SplitResult, str]:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except (ValueError, TypeError) as exc:
        raise ValueError("Review URL has an invalid host or port") from exc
    if parsed.scheme not in {"https", "http"} or not host or parsed.username or parsed.password:
        raise ValueError("Review URL must be an HTTP(S) URL without embedded credentials")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        raise ValueError("Review URL host is invalid")
    return parsed, host.lower() + (f":{port}" if port else "")


def repository_location(url: object, host: str) -> SplitResult:
    if not isinstance(url, str):
        raise RuntimeError("Provider metadata lacks a repository URL")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc.lower() != host
        or parsed.username
        or parsed.password
    ):
        raise RuntimeError("Provider repository URL does not match the requested HTTPS host")
    if parsed.query or parsed.fragment:
        raise RuntimeError("Provider repository URL contains unexpected URL parameters")
    return parsed
