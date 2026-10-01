"""Drain subprocess pipes under one deadline and shared output budget."""

import os
import selectors
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Literal

ExecutionStatus = Literal["ok", "missing", "timeout", "failed", "output_limit"]


def stop_group(process: subprocess.Popen[bytes]) -> None:
    """Kill descendants sharing the owned POSIX process group."""
    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
    elif process.poll() is None:
        process.kill()


@dataclass(slots=True)
class OutputBudget:
    limit: int
    size: int = 0
    chunks: dict[str, bytearray] = field(
        default_factory=lambda: {"stdout": bytearray(), "stderr": bytearray()}
    )

    def append(self, name: str, data: bytes) -> bool:
        self.chunks[name].extend(data[: max(0, self.limit - self.size)])
        self.size += len(data)
        return self.size <= self.limit


def register_pipes(selector, process, input_bytes: bytes) -> None:
    for name in ("stdout", "stderr"):
        stream = getattr(process, name)
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, (name, stream))
    if input_bytes:
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, ("stdin", process.stdin))
    else:
        process.stdin.close()


def close_pipe(selector, key) -> None:
    selector.unregister(key.fileobj)
    key.data[1].close()


def write_input(selector, key, input_bytes: bytes, offset: int) -> int:
    try:
        offset += os.write(key.fd, input_bytes[offset : offset + 65536])
    except BrokenPipeError:
        offset = len(input_bytes)
    if offset == len(input_bytes):
        close_pipe(selector, key)
    return offset


def read_output(selector, key, budget: OutputBudget) -> bool:
    data = os.read(key.fd, 65536)
    if not data:
        close_pipe(selector, key)
        return True
    return budget.append(key.data[0], data)


def drain(selector, budget: OutputBudget, input_bytes: bytes, deadline: float) -> ExecutionStatus:
    offset = 0
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout"
        for key, _ in selector.select(min(remaining, 0.1)):
            if key.data[0] == "stdin":
                offset = write_input(selector, key, input_bytes, offset)
            elif not read_output(selector, key, budget):
                return "output_limit"
    return "ok"


def capture(
    process: subprocess.Popen[bytes], deadline: float, limit: int, input_bytes: bytes
) -> tuple[ExecutionStatus, dict[str, bytearray]]:
    budget = OutputBudget(limit)
    with selectors.DefaultSelector() as selector:
        register_pipes(selector, process, input_bytes)
        status = drain(selector, budget, input_bytes, deadline)
    if status == "ok":
        try:
            process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            status = "timeout"
    return status, budget.chunks
