"""Write captured source bytes into an owned snapshot."""

from pathlib import Path


def write_entry(destination: Path, path: str, mode: str, content: bytes) -> None:
    output = destination / path
    output.parent.mkdir(parents=True, exist_ok=True)
    if mode == "120000":
        output.symlink_to(content.decode("utf-8", "surrogateescape"))
    else:
        output.write_bytes(content)
        output.chmod(0o755 if mode == "100755" else 0o644)
