"""Own a bounded installed process and return redacted execution evidence."""

import math
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

from diff_gremlin.domain.process import RunResult
from diff_gremlin.runtime.environment import (
    _executable,
    minimal_environment,
    redact,
    trusted_path,
)
from diff_gremlin.runtime.streams import capture, stop_group


def validate(command: Sequence[str], timeout: float, output_limit: int) -> None:
    if (
        isinstance(command, (str, bytes))
        or not command
        or any(not isinstance(arg, str) or "\0" in arg for arg in command)
    ):
        raise ValueError(
            "process command must contain nonempty, NUL-free string arguments"
        )
    if not math.isfinite(timeout) or timeout <= 0 or output_limit <= 0:
        raise ValueError(
            "process timeout and output limit must be positive finite bounds"
        )


def launch_arguments(
    executable: str, arguments: Sequence[str], file_limit: int | None
) -> list[str]:
    launch = [executable, *arguments]
    if file_limit is None or os.name != "posix":
        return launch
    driver = "import os,resource,sys;bound=int(sys.argv[1]);resource.setrlimit(resource.RLIMIT_FSIZE,(bound,bound));os.execv(sys.argv[2],sys.argv[2:])"
    return [sys.executable, "-I", "-c", driver, str(file_limit), *launch]


def start(launch: list[str], cwd: Path | None, environment: dict[str, str]):
    return subprocess.Popen(
        launch,
        cwd=cwd,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )


def finish(process) -> None:
    stop_group(process)
    process.wait()
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            stream.close()


def decoded_output(
    chunks: dict[str, bytearray],
    *,
    env: Mapping[str, str] | None,
    protect_stdout: bool,
    status: str,
    limit: int,
) -> tuple[str, str]:
    stdout = chunks["stdout"].decode("utf-8", "surrogateescape")
    if protect_stdout:
        stdout = redact(stdout, env)
    stderr = redact(chunks["stderr"].decode("utf-8", "surrogateescape"), env)
    if status != "ok":
        stderr = (stderr + f"\nProcess stopped: {status}").strip()
    stdout_bytes = stdout.encode("utf-8", "surrogateescape")[:limit]
    stderr_bytes = stderr.encode("utf-8", "surrogateescape")[
        : max(0, limit - len(stdout_bytes))
    ]
    return stdout_bytes.decode("utf-8", "surrogateescape"), stderr_bytes.decode(
        "utf-8", "surrogateescape"
    )


def run_owned(
    command: Sequence[str],
    *,
    cwd: Path | None,
    timeout: float,
    env: Mapping[str, str] | None,
    output_limit: int,
    input_text: str | None,
    protect_stdout: bool,
    file_limit: int | None,
    started: float,
    workspace: Path,
) -> RunResult:
    args = tuple(redact(arg, env) for arg in command)
    environment = minimal_environment(workspace, cwd)
    environment.update(env or {})
    executable = _executable(command[0], cwd, trusted_path(cwd))
    if executable is None:
        return RunResult(
            args,
            None,
            stderr="Installed executable unavailable or inside target",
            status="missing",
            duration_seconds=time.monotonic() - started,
        )
    try:
        process = start(
            launch_arguments(executable, command[1:], file_limit), cwd, environment
        )
    except OSError as error:
        status = "missing" if isinstance(error, FileNotFoundError) else "failed"
        return RunResult(
            args,
            None,
            stderr=f"Process launch failed: {error.strerror}",
            status=status,
            duration_seconds=time.monotonic() - started,
        )
    try:
        status, chunks = capture(
            process,
            started + timeout,
            output_limit,
            (input_text or "").encode("utf-8", "surrogateescape"),
        )
    finally:
        finish(process)
    stdout, stderr = decoded_output(
        chunks,
        env=env,
        protect_stdout=protect_stdout,
        status=status,
        limit=output_limit,
    )
    return RunResult(
        args, process.returncode, stdout, stderr, status, time.monotonic() - started
    )


def execute(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float = 120.0,
    env: Mapping[str, str] | None = None,
    output_limit: int = 4194304,
    input_text: str | None = None,
    protect_stdout: bool = True,
    file_limit: int | None = None,
) -> RunResult:
    validate(command, timeout, output_limit)
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="diff-gremlin-process-") as directory:
        return run_owned(
            command,
            cwd=cwd,
            timeout=timeout,
            env=env,
            output_limit=output_limit,
            input_text=input_text,
            protect_stdout=protect_stdout,
            file_limit=file_limit,
            started=started,
            workspace=Path(directory),
        )
