"""Observe bounded Python decision complexity from read-only Git objects."""

import ast
import re
import time
from functools import partial
from pathlib import Path

from diff_gremlin.analyzers.status import unavailable
from diff_gremlin.analyzers.versions import tool_version
from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.stages import StageResult

_ID = "history.git"
_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_MAX_FILES = 500
_IGNORED_PARTS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "tests",
        "test",
        "testing",
        "migrations",
    }
)


def _production_python(path: str) -> bool:
    file = Path(path)
    return (
        file.suffix == ".py"
        and not _IGNORED_PARTS.intersection(file.parts)
        and not file.name.startswith("test_")
        and not file.name.endswith("_test.py")
    )


def _decision_increment(node: ast.AST) -> int:
    if isinstance(
        node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler)
    ):
        return 1
    if isinstance(node, ast.BoolOp):
        return len(node.values) - 1
    if isinstance(node, ast.comprehension):
        return 1 + len(node.ifs)
    if isinstance(node, ast.match_case):
        # A final wildcard case is the default branch, rather than another decision.
        return int(
            not (isinstance(node.pattern, ast.MatchAs) and node.pattern.pattern is None)
        ) + int(node.guard is not None)
    return 0


def _function_complexity(node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    score = 1
    pending: list[ast.AST] = list(node.body)
    while pending:
        child = pending.pop()
        if isinstance(
            child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            continue
        score += _decision_increment(child)
        pending.extend(ast.iter_child_nodes(child))
    return score


def _source_observations(text: str) -> list[int]:
    if "\ufffd" in text:
        raise ValueError("undecodable Python source")
    tree = ast.parse(text)
    return [
        _function_complexity(node)
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _tree_entries(text: str) -> list[tuple[str, str]]:
    entries = []
    for record in text.split("\x00"):
        if not record:
            continue
        metadata, path = record.split("\t", 1)
        mode, kind, sha = metadata.split(" ")
        if not _SHA.fullmatch(sha):
            raise ValueError("invalid Git object identity")
        if mode in ("100644", "100755") and kind == "blob" and _production_python(path):
            entries.append((sha, path))
    if len(entries) > _MAX_FILES:
        raise ValueError("history commit exceeds bounded Python file inventory")
    return entries


def _blob_contents(text: str, entries: list[tuple[str, str]]) -> list[str]:
    payload = text.encode("utf-8")
    position = 0
    contents = []
    for sha, _ in entries:
        end = payload.index(b"\n", position)
        header = payload[position:end].decode("ascii").split(" ")
        if len(header) != 3 or header[:2] != [sha, "blob"]:
            raise ValueError("Git batch object identity mismatch")
        size = int(header[2])
        if size < 0 or size > 1024 * 1024:
            raise ValueError("history Python blob exceeds size bound")
        position = end + 1
        body = payload[position : position + size]
        position += size
        if payload[position : position + 1] != b"\n":
            raise ValueError("truncated Git batch object")
        position += 1
        contents.append(body.decode("utf-8"))
    if position != len(payload):
        raise ValueError("unexpected Git batch output")
    return contents


def _commit_row(sha: str, timestamp: int, contents: list[str]) -> dict:
    values = []
    analyzed = 0
    for text in contents:
        values.extend(_source_observations(text))
        analyzed += 1
    return {
        "commit": sha,
        "timestamp": timestamp,
        "files": analyzed,
        "functions": len(values),
        "average_cc": sum(values) / len(values) if values else 0.0,
        "max_cc": max(values, default=0),
    }


def analyze_history(
    ctx: ScanContext,
    history_repo: Path | None = None,
    *,
    limit: int = 10,
    revision: str | None = None,
) -> StageResult:
    failure = partial(
        unavailable, _ID, "Python complexity history", "history", "git", required=False
    )
    if type(limit) is not int or not 1 <= limit <= 50:
        return failure(reason="History limit must be between 1 and 50", status="failed")
    if revision is not None and (
        not isinstance(revision, str) or not _SHA.fullmatch(revision)
    ):
        return failure(
            reason="History revision must be a full immutable commit ID",
            status="failed",
        )
    if not any(file.language == "python" for file in ctx.production_files):
        return failure(
            reason="History measure supports production Python only",
            status="unsupported",
        )
    repo = history_repo if history_repo is not None else ctx.root
    deadline = time.monotonic() + ctx.timeout

    def git(*args: str, input_text: str | None = None, allow_missing: bool = False):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("bounded history deadline expired")
        result = ctx.run(
            [
                "git",
                "--no-pager",
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                str(repo),
                *args,
            ],
            cwd=ctx.scratch,
            timeout=remaining,
            input_text=input_text,
        )
        if (
            allow_missing
            and result.status == "ok"
            and result.returncode == 1
            and not result.stdout
        ):
            return ""
        if result.status != "ok" or result.returncode != 0:
            if result.status == "missing":
                raise FileNotFoundError("Git is not installed")
            if result.status == "timeout":
                raise TimeoutError("Git history operation timed out")
            raise ValueError("Git history operation failed")
        return result.stdout

    rows = []
    shallow = False
    try:
        inside = git("rev-parse", "--is-inside-work-tree").strip()
        if (
            inside != "true"
            and git("rev-parse", "--is-bare-repository").strip() != "true"
        ):
            raise ValueError("history source is not a Git repository")
        shallow_text = git("rev-parse", "--is-shallow-repository").strip()
        if shallow_text not in ("true", "false"):
            raise ValueError("invalid shallow history metadata")
        shallow = shallow_text == "true"
        anchor = git(
            "rev-parse",
            "--verify",
            "--quiet",
            f"{revision or 'HEAD'}^{{commit}}",
            allow_missing=revision is None,
        ).strip()
        if not anchor:
            return failure(
                reason="Git repository has no committed history", status="unsupported"
            )
        if not _SHA.fullmatch(anchor) or (revision is not None and anchor != revision):
            raise ValueError("history commit identity mismatch")
        commits = git(
            "log",
            "--first-parent",
            f"--max-count={limit}",
            "--format=%H %ct",
            anchor,
            "--",
        )
        identities = []
        for line in commits.splitlines():
            sha, timestamp = line.split(" ")
            if not _SHA.fullmatch(sha) or not timestamp.isdecimal():
                raise ValueError("invalid commit history metadata")
            identities.append((sha, int(timestamp)))
        for sha, timestamp in reversed(identities):
            entries = _tree_entries(git("ls-tree", "-r", "-z", sha))
            contents = (
                _blob_contents(
                    git(
                        "cat-file",
                        "--batch",
                        input_text="".join(f"{blob}\n" for blob, _ in entries),
                    ),
                    entries,
                )
                if entries
                else []
            )
            rows.append(_commit_row(sha, timestamp, contents))
    except FileNotFoundError:
        return failure(reason="Git is not installed", status="missing")
    except TimeoutError:
        return failure(
            reason="Bounded Git history analysis timed out", status="timeout"
        )
    except (ValueError, UnicodeError, SyntaxError, RecursionError, MemoryError):
        return failure(
            reason="Git history or Python object analysis failed validation",
            status="failed",
        )
    if not rows:
        return failure(
            reason="No commits available for history analysis", status="unsupported"
        )
    limited = shallow or len(rows) == 1
    reason = (
        "Shallow history exposes only the available commit window"
        if shallow
        else ("One commit provides no trend comparison" if len(rows) == 1 else "")
    )
    return StageResult(
        _ID,
        "Python complexity history",
        "history",
        "limited" if limited else "ok",
        "git",
        version=tool_version(ctx, "git"),
        required=False,
        scope="history",
        metrics={
            "rows": rows,
            "commit_count": len(rows),
            "shallow": shallow,
            "limit": limit,
            "revision": anchor,
            "measure": "python-ast-decision-complexity-v1",
            "order": "oldest-first",
            "traversal": "first-parent",
        },
        reason=reason,
        analyzed_files=rows[-1]["files"],
        eligible_files=rows[-1]["files"],
    )
