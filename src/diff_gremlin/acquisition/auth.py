"""Own short-lived Git authentication for one HTTPS repository host."""

import tempfile
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from diff_gremlin.process import run
from diff_gremlin.providers.auth import provider_environment, remote_provider


def _token(host: str, provider: str, timeout: float) -> str:
    env = provider_environment(host, provider)
    for key in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GITLAB_TOKEN",
        "GLAB_TOKEN",
    ):
        if env.get(key):
            return env[key]
    cli = "gh" if provider == "github" else "glab"
    request = f"protocol=https\nhost={host}\n\n"
    command = [cli, "auth", "git-credential", "get"]
    result = run(command, env=env, input_text=request, timeout=timeout)
    if result.status != "ok" or result.returncode != 0:
        return ""  # Anonymous fetch remains valid; failure is surfaced by the fetch.
    for line in result.stdout.splitlines():
        if line.startswith("password="):
            return line.removeprefix("password=")
    return ""


@contextmanager
def git_auth(url: str, *, timeout: float = 10.0):
    """The generated askpass script releases a token only for the exact host."""
    if urlsplit(url).scheme != "https":
        yield {}
        return
    host, provider = remote_provider(url)
    token = _token(host, provider, timeout)
    if not token:
        yield {}
        return
    with tempfile.TemporaryDirectory(prefix="diff-gremlin-auth-") as directory:
        root = Path(directory)
        secret = root / "credential"
        secret.write_text(token)
        secret.chmod(0o600)
        script = root / "askpass"
        # This is our fixed transport, never a repository-supplied helper.
        script.write_text(
            "#!/usr/bin/env python3\n"
            "import os, sys\nfrom urllib.parse import urlsplit\n"
            "prompt = sys.argv[1] if len(sys.argv)>1 else ''\n"
            "url = prompt.split(\"'\")[1] if \"'\" in prompt else ''\n"
            "if urlsplit(url).netloc.rsplit('@',1)[-1].lower() != os.environ['DIFF_GREMLIN_AUTH_HOST']:\n"
            "    sys.exit(1)\n"
            "if prompt.startswith('Username'):\n    print('oauth2')\n"
            "elif prompt.startswith('Password'):\n"
            "    with open(os.environ['DIFF_GREMLIN_AUTH_FILE']) as stream: print(stream.read())\n"
            "else:\n    sys.exit(1)\n"
        )
        script.chmod(0o700)
        yield {
            "GIT_ASKPASS": str(script),
            "DIFF_GREMLIN_AUTH_FILE": str(secret),
            "DIFF_GREMLIN_AUTH_HOST": host,
        }
