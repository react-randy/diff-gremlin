"""Read static Python history with one deadline and immutable Git identities."""

import time
from pathlib import Path

from diff_gremlin.analyzers.history_measure import commit_observations
from diff_gremlin.analyzers.history_objects import (
    blob_contents,
    is_object_id,
    python_entries,
)
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.process import RunResult


def commit_identities(text: str) -> list[tuple[str, int]]:
    identities = []
    for line in text.splitlines():
        sha, timestamp = line.split(" ")
        if not is_object_id(sha) or not timestamp.isdecimal():
            raise ValueError("invalid commit history metadata")
        identities.append((sha, int(timestamp)))
    return identities


def checked_output(result: RunResult, allow_missing: bool) -> str:
    """Validate Git transport evidence before consuming source metadata."""
    if allow_missing and result.status == "ok" and result.returncode == 1 and not result.stdout:
        return ""
    if result.status == "ok" and result.returncode == 0:
        return result.stdout
    if result.status == "missing":
        raise FileNotFoundError("Git is not installed")
    if result.status == "timeout":
        raise TimeoutError("Git history operation timed out")
    raise ValueError("Git history operation failed")


class HistoryReader:
    """Retrieve bounded source blobs without checking out or executing history."""

    def __init__(self, ctx: ScanContext, repo: Path):
        self.ctx = ctx
        self.repo = repo
        self.deadline = time.monotonic() + ctx.timeout

    def git(self, *args: str, input_text: str | None = None, allow_missing: bool = False) -> str:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("bounded history deadline expired")
        result = self.ctx.run(
            [
                "git",
                "--no-pager",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(self.repo),
                *args,
            ],
            cwd=self.ctx.scratch,
            timeout=remaining,
            input_text=input_text,
            data_output=bool(args and args[0] == "cat-file"),
        )
        return checked_output(result, allow_missing)

    def is_repository(self) -> bool:
        inside = self.git("rev-parse", "--is-inside-work-tree").strip()
        return inside == "true" or self.git("rev-parse", "--is-bare-repository").strip() == "true"

    def is_shallow(self) -> bool:
        value = self.git("rev-parse", "--is-shallow-repository").strip()
        if value not in ("true", "false"):
            raise ValueError("invalid shallow history metadata")
        return value == "true"

    def revision(self, requested: str | None) -> str:
        anchor = self.git(
            "rev-parse",
            "--verify",
            "--quiet",
            f"{requested or 'HEAD'}^{{commit}}",
            allow_missing=requested is None,
        ).strip()
        if not anchor:
            return ""
        if not is_object_id(anchor) or (requested is not None and anchor != requested):
            raise ValueError("history commit identity mismatch")
        return anchor

    def commit_contents(self, sha: str) -> list[str]:
        entries = python_entries(self.git("ls-tree", "-r", "-z", sha))
        if not entries:
            return []
        result = self.git(
            "cat-file",
            "--batch",
            input_text="".join(f"{blob}\n" for blob, _ in entries),
        )
        return blob_contents(result, entries)

    def rows(self, anchor: str, limit: int) -> list[dict]:
        text = self.git(
            "log",
            "--first-parent",
            f"--max-count={limit}",
            "--format=%H %ct",
            anchor,
            "--",
        )
        return [
            commit_observations(sha, timestamp, self.commit_contents(sha))
            for sha, timestamp in reversed(commit_identities(text))
        ]
