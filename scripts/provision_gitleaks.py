"""Provision one checksum-verified official Gitleaks executable."""

import argparse
import hashlib
import importlib.util
import io
import platform
import tarfile
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


VERSION = "8.30.1"
ARCHIVES = {
    "linux_x64": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    "linux_arm64": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
    "darwin_x64": "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
    "darwin_arm64": "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
}


def archive_name() -> str:
    """Identify a supported official archive for this process architecture."""
    system = platform.system().lower()
    machine = {"x86_64": "x64", "AMD64": "x64", "aarch64": "arm64"}.get(
        platform.machine(), platform.machine()
    )
    name = f"{system}_{machine}"
    if name not in ARCHIVES:
        raise ValueError(f"Gitleaks {VERSION} installer does not support {name}")
    return name


def download(name: str) -> bytes:
    """Read a bounded official release archive over HTTPS."""
    url = (
        f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/"
        f"gitleaks_{VERSION}_{name}.tar.gz"
    )
    return transfer_helper().download(url, 32 * 1024 * 1024)


def verify(data: bytes, name: str) -> None:
    """Reject archive bytes that do not match reviewed release metadata."""
    if hashlib.sha256(data).hexdigest() != ARCHIVES[name]:
        raise ValueError(f"Gitleaks {VERSION} archive checksum mismatch for {name}")


def member_bytes(archive: tarfile.TarFile, name: str) -> bytes:
    """Read one regular member without extracting archive paths or links."""
    member = archive.getmember(name)
    if not member.isfile() or member.size > 64 * 1024 * 1024:
        raise ValueError(f"Gitleaks archive has an invalid {name} member")
    stream = archive.extractfile(member)
    if stream is None:
        raise ValueError(f"Gitleaks archive is missing readable {name}")
    with stream:
        return stream.read()


def provision(destination: Path) -> None:
    """Place the verified executable and its license in a tool directory."""
    name = archive_name()
    data = download(name)
    verify(data, name)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        executable = member_bytes(archive, "gitleaks")
        license_text = member_bytes(archive, "LICENSE")
    destination.mkdir(parents=True, exist_ok=True)
    binary = destination / "gitleaks"
    binary.write_bytes(executable)
    binary.chmod(0o755)
    (destination / "GITLEAKS-LICENSE").write_bytes(license_text)


def main() -> int:
    """Expose provisioning as a build/installation step."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    try:
        provision(arguments.destination)
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(1, f"Gitleaks installation failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
