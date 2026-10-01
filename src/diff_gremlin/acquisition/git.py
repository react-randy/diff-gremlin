"""Run read-only Git operations with configuration and execution hooks disabled."""

import math
import os
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

from diff_gremlin.process import _execute

GIT_OPTIONS = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.attributesFile=/dev/null",
    "-c",
    "credential.helper=",
    "-c",
    "core.sshCommand=false",
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "protocol.http.allow=always",
    "-c",
    "http.followRedirects=false",
    "-c",
    "fetch.fsckObjects=true",
    "-c",
    "transfer.fsckObjects=true",
    "-c",
    "gc.auto=0",
]
GIT_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_NO_REPLACE_OBJECTS": "1",
    "GIT_NO_LAZY_FETCH": "1",
}


class Git:
    """Share one acquisition deadline across bounded object operations."""

    def __init__(self, timeout: float):
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Acquisition timeout must be positive and finite")
        self.deadline = time.monotonic() + timeout

    def run(
        self,
        args: list[str],
        *,
        cwd: Path | None = None,
        env: dict | None = None,
        limit: int = 4194304,
        data: bool = False,
        input_text: str | None = None,
    ) -> str:
        remaining = self.remaining()
        trust = ["-c", f"safe.directory={cwd.resolve()}"] if cwd else []
        result = _execute(
            ["git", *GIT_OPTIONS, *trust, *args],
            cwd=cwd,
            timeout=remaining,
            env={**GIT_ENV, **(env or {})},
            output_limit=limit,
            protect_stdout=not data,
            input_text=input_text,
            file_limit=1024 * 1024 * 1024,
        )
        if result.status != "ok" or result.returncode != 0:
            raise RuntimeError(
                f"Git {args[0]} failed ({result.status}); verify the requested local objects or remote access"
            )
        return result.stdout

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Source acquisition timed out")
        return remaining

    def resolve(self, repo: Path, ref: str) -> str:
        if not ref or "\0" in ref or ref.startswith("-"):
            raise ValueError("Git ref must be a nonempty object ID or ref name")
        value = self.run(
            ["rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"], cwd=repo
        ).strip()
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value):
            raise RuntimeError("Git did not return a full commit object ID")
        return value

    def date(self, repo: Path, commit: str) -> str:
        return self.run(["show", "-s", "--format=%cI", commit], cwd=repo).strip()


def remote_url(target: str) -> str | None:
    if "://" not in target and not target.startswith("git@"):
        return None
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(
            "Remote acquisition requires an HTTP(S) repository URL; use a local checkout for SSH repositories"
        )
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            "Repository URLs must not contain credentials or URL parameters"
        )
    try:
        _port = parsed.port
    except ValueError as exc:
        raise ValueError("Repository URL has an invalid port") from exc
    return target.rstrip("/")
