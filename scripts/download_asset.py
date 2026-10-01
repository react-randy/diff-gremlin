"""Download bounded HTTPS bytes within one supervised transfer deadline."""

import argparse
import math
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEADLINE_SECONDS = 60
BYTE_LIMIT_EXIT = 3
HTTPS_EXIT = 4
TRANSFER_EXIT = 5


def require_https(url: str) -> None:
    """Reject unsupported protocols before opening a connection or redirect."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("asset download requires HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("asset download does not accept URL credentials")


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    """Validate each redirect before urllib opens its destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def transfer(url: str, limit: int, destination: Path) -> int:
    """Stream at most the byte limit into one parent-owned temporary file."""
    try:
        require_https(url)
        opener = urllib.request.build_opener(HTTPSRedirects())
        with opener.open(url, timeout=DEADLINE_SECONDS) as response:
            require_https(response.geturl())
            with destination.open("xb") as stream:
                remaining = limit
                while data := response.read(min(64 * 1024, remaining + 1)):
                    if len(data) > remaining:
                        return BYTE_LIMIT_EXIT
                    stream.write(data)
                    remaining -= len(data)
    except ValueError:
        return HTTPS_EXIT
    except (OSError, urllib.error.URLError):
        return TRANSFER_EXIT
    return 0


def download(url: str, limit: int, timeout: float = DEADLINE_SECONDS) -> bytes:
    """Kill and reap the isolated worker when the total transfer deadline expires."""
    require_https(url)
    if limit <= 0 or not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("asset download requires positive byte and time limits")
    with tempfile.TemporaryDirectory(prefix="asset-download-") as directory:
        output = Path(directory) / "asset"
        command = [sys.executable, "-I", str(Path(__file__).resolve())]
        command.extend(["--worker", url, str(limit), str(output)])
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise TimeoutError(
                "asset download exceeded total transfer deadline"
            ) from None
        failures = {
            BYTE_LIMIT_EXIT: "asset download exceeds byte limit",
            HTTPS_EXIT: "asset download requires HTTPS throughout redirects",
            TRANSFER_EXIT: "asset download failed during HTTPS transfer",
        }
        if result.returncode:
            raise ValueError(
                failures.get(result.returncode, "asset download worker failed")
            )
        with output.open("rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("asset download exceeds byte limit")
        return data


def main() -> int:
    """Expose only the transfer worker used by the supervising owned helper."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true", required=True)
    parser.add_argument("url")
    parser.add_argument("limit", type=int)
    parser.add_argument("destination", type=Path)
    arguments = parser.parse_args()
    if arguments.limit <= 0:
        parser.error("byte limit must be positive")
    return transfer(arguments.url, arguments.limit, arguments.destination)


if __name__ == "__main__":
    raise SystemExit(main())
