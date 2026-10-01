"""Provision the pinned official shfmt executable and its BSD license."""

import argparse
import hashlib
import importlib.util
import os
import platform
import tempfile
from pathlib import Path


def transfer_helper():
    """Load only the verified sibling, including under isolated Python (-I)."""
    directory = Path(__file__).resolve().parent
    path = directory / "download_asset.py"
    if not path.is_file() or path.resolve().parent != directory:
        raise ValueError(
            "verified sibling download_asset.py is missing or outside scripts"
        )
    spec = importlib.util.spec_from_file_location("_owned_asset_download", path)
    if spec is None or spec.loader is None:
        raise ValueError("verified sibling download_asset.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERSION = "3.14.1"
COMMIT = "a3f0c75d21d918756fa38de8b5d3429efde7948b"
LICENSE_SHA256 = "ce63850f77649f00d1394045e2794ffb09a5596beabac51c9548edd958845d7c"
ARTIFACTS = {
    "linux_amd64": "76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf",
    "linux_arm64": "5f2db09dae91fca848f7adbdd014632e921a383863a2ad7e0450ad3aba0c6489",
    "darwin_amd64": "d33eee0da0f92835b3562e9767a05cee7e4eaeef47daa03bfd09da17b4b590a6",
    "darwin_arm64": "b7c872db63553ccffc7253aba3ed7d4885a27d83f1ba567b1138c6315a5847e5",
}


def artifact_name() -> str:
    """Select only the four reviewed OS and architecture artifacts."""
    machine = {"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64"}.get(
        platform.machine(), platform.machine()
    )
    name = f"{platform.system().lower()}_{machine}"
    if name not in ARTIFACTS:
        raise ValueError(f"shfmt {VERSION} installer does not support {name}")
    return name


def download(url: str, limit: int) -> bytes:
    """Read bounded bytes from an official fixed HTTPS source."""
    return transfer_helper().download(url, limit)


def verify(data: bytes, digest: str, label: str) -> None:
    """Reject changed bytes before any installation write or executable mode."""
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"shfmt {label} checksum mismatch")


def prepared_file(destination: Path, data: bytes, mode: int) -> Path:
    """Stage verified bytes in the owned destination for an atomic replacement."""
    descriptor, name = tempfile.mkstemp(prefix=".shfmt-", dir=destination)
    path = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(mode)
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def publish(destination: Path, executable: bytes, license_text: bytes) -> None:
    """Publish the license before the executable; name partial publication errors."""
    destination.mkdir(parents=True, exist_ok=True)
    staged = []
    license_published = False
    try:
        staged.append(prepared_file(destination, license_text, 0o644))
        staged.append(prepared_file(destination, executable, 0o755))
        staged[0].replace(destination / "SHFMT-LICENSE")
        license_published = True
        staged[1].replace(destination / "shfmt")
    except OSError as error:
        state = (
            "license published; executable publication incomplete"
            if license_published
            else "publication incomplete"
        )
        raise OSError(f"shfmt {state}") from error
    finally:
        for path in staged:
            path.unlink(missing_ok=True)


def provision(destination: Path) -> None:
    """Verify both fixed upstream assets before touching the destination."""
    name = artifact_name()
    url = f"https://github.com/mvdan/sh/releases/download/v{VERSION}/shfmt_v{VERSION}_{name}"
    executable = download(url, 8 * 1024 * 1024)
    verify(executable, ARTIFACTS[name], "executable")
    license_text = download(
        f"https://raw.githubusercontent.com/mvdan/sh/{COMMIT}/LICENSE", 64 * 1024
    )
    verify(license_text, LICENSE_SHA256, "license")
    publish(destination, executable, license_text)


def main() -> int:
    """Expose one standalone build and installation step without package imports."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    try:
        provision(arguments.destination)
    except (OSError, ValueError) as error:
        parser.exit(1, f"shfmt installation failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
