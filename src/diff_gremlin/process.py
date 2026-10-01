"""Execute installed tools with bounded resources and a minimal environment."""

import math
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from diff_gremlin.domain.process import RunResult

ExecutionStatus = Literal["ok", "missing", "timeout", "failed", "output_limit"]

_SECRET_KEY = re.compile(
    r"token|password|secret|credential|authorization|api[_-]?key", re.IGNORECASE
)


def redact(text: str, env: Mapping[str, str] | None = None) -> str:
    """Remove credential values and URL user information from diagnostic text."""
    for source in (os.environ, env or {}):
        for key, value in source.items():
            if value and _SECRET_KEY.search(key):
                text = text.replace(value, "[redacted]")
    return re.sub(r"(https?://)[^/\s@]+@", r"\1[redacted]@", text)


def trusted_path(cwd: Path | None = None) -> str:
    """Exclude relative search paths and executable directories inside the target."""
    root = cwd.resolve() if cwd else None
    candidates = [str(Path(sys.executable).parent), *os.defpath.split(os.pathsep)]
    candidates.extend(os.environ.get("DIFF_GREMLIN_TOOL_PATH", "").split(os.pathsep))
    paths = []
    for entry in candidates:
        directory = Path(entry)
        if not entry or not directory.is_absolute():
            continue
        resolved = directory.resolve()
        if root and (resolved == root or root in resolved.parents):
            continue
        if str(resolved) not in paths:
            paths.append(str(resolved))
    return os.pathsep.join(paths)


def minimal_environment(home: Path, cwd: Path | None = None) -> dict[str, str]:
    """Keep tool configuration and credentials outside the analyzer environment."""
    return {
        "PATH": trusted_path(cwd),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_CACHE_HOME": str(home / "cache"),
        "TMPDIR": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "NO_COLOR": "1",
        "CI": "true",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }


def _executable(name: str, cwd: Path | None, path: str) -> str | None:
    candidate = Path(name)
    if candidate.is_absolute():
        resolved = candidate.resolve()
        lexical = candidate.absolute()
        if cwd and any(
            path == cwd.resolve() or cwd.resolve() in path.parents
            for path in (resolved, lexical)
        ):
            return None
        return str(resolved)
    if candidate.name != name:
        return None
    executable = shutil.which(name, path=path)
    if executable and cwd and cwd.resolve() in Path(executable).resolve().parents:
        return None
    return executable


def _stop_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
    elif process.poll() is None:
        process.kill()


def _capture(
    process: subprocess.Popen[bytes], deadline: float, limit: int, input_bytes: bytes
) -> tuple[ExecutionStatus, dict[str, bytearray]]:
    """Drain both output streams while enforcing a shared byte budget."""
    assert process.stdin is not None
    chunks: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    size = 0
    status: ExecutionStatus = "ok"
    with selectors.DefaultSelector() as selector:
        for name in chunks:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if input_bytes:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
        offset = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "timeout"
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                if key.data == "stdin":
                    try:
                        offset += os.write(key.fd, input_bytes[offset : offset + 65536])
                    except BrokenPipeError:
                        offset = len(input_bytes)
                    if offset == len(input_bytes):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                available = max(0, limit - size)
                chunks[key.data].extend(data[:available])
                size += len(data)
                if size > limit:
                    status = "output_limit"
                    break
            if status != "ok":
                break
    if status == "ok":
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            status = "timeout"
    return status, chunks


def _execute(
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
    """Run a trusted installed executable without a shell; nonzero exits are completed."""
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
    started = time.monotonic()
    args = tuple(redact(arg, env) for arg in command)
    with tempfile.TemporaryDirectory(prefix="diff-gremlin-process-") as directory:
        child_env = minimal_environment(Path(directory), cwd)
        if env:
            child_env.update(env)
        # An explicit environment does not authorize a repository-local executable.
        executable = _executable(command[0], cwd, trusted_path(cwd))
        if executable is None:
            return RunResult(
                args,
                None,
                stderr="Installed executable unavailable or inside target",
                status="missing",
                duration_seconds=time.monotonic() - started,
            )
        launch = [executable, *command[1:]]
        if file_limit is not None and os.name == "posix":
            # A trusted interpreter launcher avoids unsafe threaded preexec callbacks.
            launch = [
                sys.executable,
                "-I",
                "-c",
                (
                    "import os,resource,sys;"
                    "bound=int(sys.argv[1]);"
                    "resource.setrlimit(resource.RLIMIT_FSIZE,(bound,bound));"
                    "os.execv(sys.argv[2],sys.argv[2:])"
                ),
                str(file_limit),
                *launch,
            ]
        try:
            process = subprocess.Popen(
                launch,
                cwd=cwd,
                env=child_env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=os.name == "posix",
            )
        except OSError as exc:
            status = "missing" if isinstance(exc, FileNotFoundError) else "failed"
            return RunResult(
                args,
                None,
                stderr=f"Process launch failed: {exc.strerror}",
                status=status,
                duration_seconds=time.monotonic() - started,
            )
        try:
            status, chunks = _capture(
                process,
                started + timeout,
                output_limit,
                (input_text or "").encode("utf-8", "surrogateescape"),
            )
        finally:
            _stop_group(process)
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        stdout = chunks["stdout"].decode("utf-8", "surrogateescape")
        if protect_stdout:
            stdout = redact(stdout, env)
        stderr = redact(chunks["stderr"].decode("utf-8", "surrogateescape"), env)
        if status != "ok":
            stderr = (stderr + f"\nProcess stopped: {status}").strip()
        stdout_bytes = stdout.encode("utf-8", "surrogateescape")[:output_limit]
        stderr_bytes = stderr.encode("utf-8", "surrogateescape")[
            : max(0, output_limit - len(stdout_bytes))
        ]
        stdout = stdout_bytes.decode("utf-8", "surrogateescape")
        stderr = stderr_bytes.decode("utf-8", "surrogateescape")
        return RunResult(
            args, process.returncode, stdout, stderr, status, time.monotonic() - started
        )


def run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float = 120.0,
    env: Mapping[str, str] | None = None,
    output_limit: int = 4194304,
    input_text: str | None = None,
) -> RunResult:
    """Execute a bounded installed tool and redact credential-bearing diagnostics."""
    return _execute(
        command,
        cwd=cwd,
        timeout=timeout,
        env=env,
        output_limit=output_limit,
        input_text=input_text,
    )
