"""Controlled immutable metadata covers forks, hosts, malformed shapes, and auth."""

import json

import pytest

from diff_gremlin.domain.process import RunResult
from diff_gremlin.providers import metadata
from diff_gremlin.providers.auth import provider_environment
from diff_gremlin.providers.resolve import resolve_review
from diff_gremlin.providers.urls import parse_review_url, repository_url

BASE = "a" * 40
HEAD = "b" * 40


def github_payload(host="github.com"):
    return {
        "number": 12,
        "base": {
            "sha": BASE,
            "ref": "same-name",
            "repo": {
                "full_name": "team/repo",
                "clone_url": f"https://{host}/team/repo.git",
            },
        },
        "head": {
            "sha": HEAD,
            "ref": "same-name",
            "repo": {
                "full_name": "contributor/repo",
                "clone_url": f"https://{host}/contributor/repo.git",
            },
        },
    }


def mock_metadata(monkeypatch, values):
    calls = []

    def fake(command, **kwargs):
        calls.append((command, kwargs))
        value = values.pop(0)
        return (
            value
            if isinstance(value, RunResult)
            else RunResult(tuple(command), 0, json.dumps(value))
        )

    monkeypatch.setattr(metadata, "run", fake)
    return calls


def test_github_fork_same_name_has_exact_repositories_and_shas(monkeypatch):
    calls = mock_metadata(monkeypatch, [github_payload()])
    result = resolve_review("https://github.com/team/repo/pull/12/files?diff=split#top")
    assert result.base_sha == BASE and result.head_sha == HEAD
    assert result.head_repo_url == "https://github.com/contributor/repo.git"
    assert result.base_repo_url == "https://github.com/team/repo.git"
    assert result.head_fetch_ref == "refs/pull/12/head"
    assert calls[0][0][-1] == "repos/team/repo/pulls/12"
    assert "--method" in calls[0][0]


def test_enterprise_github_and_selfmanaged_nested_gitlab(monkeypatch):
    calls = mock_metadata(monkeypatch, [github_payload("code.example.test:8443")])
    assert (
        resolve_review("https://code.example.test:8443/team/repo/pull/12").provider
        == "github"
    )
    assert calls[0][1]["env"]["GH_HOST"] == "code.example.test:8443"
    values = [
        {
            "iid": 9,
            "target_project_id": 4,
            "source_project_id": 5,
            "target_branch": "main",
            "source_branch": "main",
            "diff_refs": {"start_sha": BASE, "head_sha": HEAD, "base_sha": "c" * 40},
        },
        {
            "id": 4,
            "path_with_namespace": "group/nested/repo",
            "http_url_to_repo": "https://git.example.test:8443/group/nested/repo.git",
        },
        {
            "id": 5,
            "path_with_namespace": "fork/repo",
            "http_url_to_repo": "https://git.example.test:8443/fork/repo.git",
        },
    ]
    calls = mock_metadata(monkeypatch, values)
    result = resolve_review(
        "https://git.example.test:8443/group/nested/repo/-/merge_requests/9/diffs"
    )
    assert result.base_sha == BASE  # target start SHA, deliberately not diff merge-base
    assert result.head_repo_url.endswith("/fork/repo.git")
    assert calls[0][0][-1] == "projects/group%2Fnested%2Frepo/merge_requests/9"
    assert len(calls) == 3


@pytest.mark.parametrize(
    "value", [None, [], "text", {}, {"number": 12}, {"number": 12, "base": []}]
)
def test_wrong_metadata_shapes_have_typed_errors(value, monkeypatch):
    mock_metadata(monkeypatch, [value])
    with pytest.raises(RuntimeError, match=r"metadata|object"):
        resolve_review("https://github.com/team/repo/pull/12")


@pytest.mark.parametrize("mutation", ["sha", "host", "target", "head"])
def test_incomplete_or_mismatched_metadata_rejected(mutation, monkeypatch):
    data = github_payload()
    if mutation == "sha":
        data["head"]["sha"] = "123"
    elif mutation == "host":
        data["head"]["repo"]["clone_url"] = "https://attacker.test/contributor/repo.git"
    elif mutation == "target":
        data["base"]["repo"]["full_name"] = "wrong/repo"
    else:
        data["head"]["repo"] = None
    mock_metadata(monkeypatch, [data])
    with pytest.raises(RuntimeError):
        resolve_review("https://github.com/team/repo/pull/12")


def test_failure_text_never_echoes_unknown_provider_credentials(monkeypatch):
    mock_metadata(
        monkeypatch, [RunResult(("gh",), 1, stderr="private-unknown-credential")]
    )
    with pytest.raises(RuntimeError) as error:
        resolve_review("https://github.com/team/repo/pull/12")
    assert "private-unknown-credential" not in str(error.value)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@github.com/team/repo/pull/12",
        "https://github.com/team/repo/pull/12evil",
        "https://github.com/team/repo/pull/0",
        "https://x/group/-/merge_requests/1evil",
        "https://x:bad/team/repo/pull/12",
        "https://x/../repo/pull/12",
    ],
)
def test_invalid_urls_do_not_echo_input(url):
    with pytest.raises(ValueError) as error:
        parse_review_url(url)
    assert url not in str(error.value)
    assert "secret" not in str(error.value)


def test_auth_is_scoped_to_exact_provider_host(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "fake-github-token")
    monkeypatch.setenv("GITLAB_TOKEN", "fake-gitlab-token")
    monkeypatch.setenv("GITLAB_HOST", "git.example.test")
    assert (
        provider_environment("github.com", "github")["GH_TOKEN"] == "fake-github-token"
    )
    assert "GH_TOKEN" not in provider_environment("enterprise.example.test", "github")
    assert "GITLAB_TOKEN" not in provider_environment("gitlab.com", "gitlab")
    assert (
        provider_environment("git.example.test", "gitlab")["GITLAB_TOKEN"]
        == "fake-gitlab-token"
    )


def test_gitlab_same_project_uses_two_metadata_requests(monkeypatch):
    values = [
        {
            "iid": 9,
            "target_project_id": 4,
            "source_project_id": 4,
            "target_branch": "main",
            "source_branch": "feature",
            "diff_refs": {"start_sha": BASE, "head_sha": HEAD},
        },
        {
            "id": 4,
            "path_with_namespace": "group/repo",
            "http_url_to_repo": "https://gitlab.com/group/repo.git",
        },
    ]
    calls = mock_metadata(monkeypatch, values)
    result = resolve_review("https://gitlab.com/group/repo/-/merge_requests/9/commits")
    assert result.base_repo_url == result.head_repo_url
    assert len(calls) == 2


@pytest.mark.parametrize("refs", [None, [], "bad", {}, {"start_sha": BASE}])
def test_gitlab_incomplete_diff_refs_do_not_become_moving_branches(refs, monkeypatch):
    values = [
        {
            "iid": 9,
            "target_project_id": 4,
            "source_project_id": 4,
            "target_branch": "main",
            "source_branch": "feature",
            "diff_refs": refs,
        },
        {
            "id": 4,
            "path_with_namespace": "group/repo",
            "http_url_to_repo": "https://gitlab.com/group/repo.git",
        },
    ]
    mock_metadata(monkeypatch, values)
    with pytest.raises(RuntimeError):
        resolve_review("https://gitlab.com/group/repo/-/merge_requests/9")


def test_malformed_json_is_safe_provider_error(monkeypatch):
    mock_metadata(monkeypatch, [RunResult(("gh",), 0, "malformed-private-secret")])
    with pytest.raises(RuntimeError) as error:
        resolve_review("https://github.com/team/repo/pull/12")
    assert "malformed-private-secret" not in str(error.value)


@pytest.mark.parametrize(
    ("url", "project", "message"),
    [
        (None, None, "lacks a repository URL"),
        ("http://github.com/team/repo.git", None, "requested HTTPS host"),
        ("https://user:secret@github.com/team/repo.git", None, "requested HTTPS host"),
        (
            "https://github.com/team/repo.git?q=secret",
            None,
            "unexpected URL parameters",
        ),
        ("https://github.com/team/repo.git#secret", None, "unexpected URL parameters"),
        ("https://github.com/team/repo.git", "other/repo", "requested project"),
        ("https://github.com/team/../repo.git", None, "project path is invalid"),
        ("https://github.com/", None, "project path is invalid"),
    ],
)
def test_repository_url_validation_preserves_typed_safe_errors(url, project, message):
    with pytest.raises(RuntimeError, match=message) as error:
        repository_url(url, "github.com", project)
    assert "secret" not in str(error.value)


def test_repository_url_normalizes_case_and_optional_git_suffix():
    assert repository_url(
        "https://GITHUB.com/Team/Repo", "github.com", "team/repo"
    ) == ("https://github.com/Team/Repo.git")
