"""Provision the reviewed standalone PHPStan PHAR with runtime license notices."""

import argparse
import hashlib
import importlib.util
import os
import tempfile
from pathlib import Path

VERSION = "2.2.15"
PHAR_SHA256 = "adccacab7cd31a262a5da17478ad5befea6f808afc32cf5f3e8af09702165f90"
PHAR_SIZE = 29_964_760
COMMIT = "b158556ffd26825cf615a1c1f72fb5157a2301b7"
LICENSE_SHA256 = "f9e4f43eb1c32f7c4f5bcdb0860de5ba71712c3c1547eeb0d1e4b3c43313ec81"
LICENSE_SIZE = 1105
PHP_COMMIT = "c31ae58ecbedc7a85dac0eee5a6a88da73543e70"
PHP_LICENSE_SHA256 = "b42e4df5e50e6ecda1047d503d6d91d71032d09ed1027ba1ef29eed26f890c5a"
PHP_LICENSE_SIZE = 3204
DOWNLOAD_HELPER_SHA256 = (
    "b5e14f72993de145781df7fb87a8bf871ef2b5702bcc2e8a5b71c756a8e8ca18"
)
PHAR_URL = (
    f"https://github.com/phpstan/phpstan/releases/download/{VERSION}/phpstan.phar"
)
LICENSE_URL = f"https://raw.githubusercontent.com/phpstan/phpstan/{COMMIT}/LICENSE"
PHP_LICENSE_URL = f"https://raw.githubusercontent.com/php/php-src/{PHP_COMMIT}/LICENSE"


def transfer_helper():
    """Load the hash-verified sibling under ordinary or isolated Python (-I)."""
    directory = Path(__file__).resolve().parent
    path = directory / "download_asset.py"
    if not path.is_file() or path.resolve().parent != directory:
        raise ValueError(
            "reviewed sibling download_asset.py is missing or outside scripts"
        )
    if hashlib.sha256(path.read_bytes()).hexdigest() != DOWNLOAD_HELPER_SHA256:
        raise ValueError("download_asset.py checksum mismatch")
    spec = importlib.util.spec_from_file_location("_owned_asset_download", path)
    if spec is None or spec.loader is None:
        raise ValueError("reviewed sibling download_asset.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def download(url: str, limit: int) -> bytes:
    """Use the existing HTTPS-only byte cap and supervised transfer deadline."""
    return transfer_helper().download(url, limit)


def verified_asset(url: str, size: int, digest: str, label: str) -> bytes:
    """Reject changed assets before touching an installation destination."""
    data = download(url, size)
    if len(data) != size:
        raise ValueError(f"{label} size mismatch")
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"{label} checksum mismatch")
    return data


def prepared_file(destination: Path, data: bytes, mode: int) -> Path:
    """Stage verified bytes beside their final atomic replacement."""
    descriptor, name = tempfile.mkstemp(prefix=".phpstan-", dir=destination)
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


def publish(destination: Path, assets: tuple[tuple[str, bytes, int], ...]) -> None:
    """Publish notices before the PHAR, naming any incomplete publication."""
    destination.mkdir(parents=True, exist_ok=True)
    staged = []
    published = []
    try:
        for name, data, mode in assets:
            staged.append((name, prepared_file(destination, data, mode)))
        for name, path in staged:
            path.replace(destination / name)
            published.append(name)
    except OSError as error:
        state = ", ".join(published) if published else "none"
        raise OSError(f"PHPStan publication incomplete; published: {state}") from error
    finally:
        for _, path in staged:
            path.unlink(missing_ok=True)


def provision(destination: Path) -> None:
    """Verify all assets; publish without executing PHP, PHAR or Composer."""
    phar = verified_asset(PHAR_URL, PHAR_SIZE, PHAR_SHA256, "PHPStan PHAR")
    license_text = verified_asset(
        LICENSE_URL, LICENSE_SIZE, LICENSE_SHA256, "PHPStan license"
    )
    php_license = verified_asset(
        PHP_LICENSE_URL, PHP_LICENSE_SIZE, PHP_LICENSE_SHA256, "PHP license"
    )
    publish(
        destination,
        (
            ("PHPSTAN-LICENSE", license_text, 0o644),
            ("PHP-LICENSE", php_license, 0o644),
            # Executable mode enables trusted tool discovery. Scanning always
            # invokes a workspace copy through explicit PHP -n, never the shebang.
            ("phpstan.phar", phar, 0o755),
        ),
    )


def main() -> int:
    """Expose one standalone build/install step with actionable errors."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    try:
        provision(arguments.destination)
    except (OSError, ValueError) as error:
        parser.exit(1, f"PHPStan installation failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
