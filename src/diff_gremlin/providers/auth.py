"""Scope provider CLI authentication to one explicit host."""

import os
from urllib.parse import urlsplit


def provider_environment(host: str, provider: str) -> dict[str, str]:
    env = {
        "HOME": os.environ.get("HOME", ""),
        "GH_HOST": host,
        "GITLAB_HOST": host,
        "GH_PROMPT_DISABLED": "1",
        "GLAB_NO_PROMPT": "1",
    }
    for key in ("XDG_CONFIG_HOME", "GH_CONFIG_DIR", "GLAB_CONFIG_DIR"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    if provider == "github":
        keys = (
            ("GH_TOKEN", "GITHUB_TOKEN")
            if host == "github.com"
            else (
                ("GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN")
                if os.environ.get("GH_HOST", "").lower() == host
                else ()
            )
        )
    else:
        configured = os.environ.get("GITLAB_HOST", "gitlab.com").lower()
        keys = ("GITLAB_TOKEN", "GLAB_TOKEN") if configured == host else ()
    for key in keys:
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


def remote_provider(url: str) -> tuple[str, str]:
    parsed = urlsplit(url)
    host = parsed.netloc.lower()
    configured_gh = os.environ.get("GH_HOST", "").lower()
    provider = "github" if host in {"github.com", configured_gh} else "gitlab"
    return host, provider
