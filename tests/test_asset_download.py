"""Native TLS deadline controls for the owned standalone provisioners."""

import hashlib
import importlib.util
import io
import shutil
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_helper(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


asset = load_helper("download_asset")


@pytest.fixture(scope="module")
def tls_server(tmp_path_factory):
    """Serve actual native TLS from a fresh locally trusted test certificate."""
    directory = tmp_path_factory.mktemp("asset-tls")
    cert, key = directory / "cert.pem", directory / "key.pem"
    openssl = shutil.which("openssl")
    assert openssl is not None, "native TLS controls require existing openssl"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            requests.append(self.path)
            if self.path.startswith("/redirect"):
                self.send_response(302)
                target = (
                    "http://127.0.0.1:9/private-response-sentinel"
                    if self.path == "/redirect-http"
                    else f"https://localhost:{self.server.server_port}/"
                    + ("slow" if self.path == "/redirect-slow" else "fast")
                )
                self.send_header("Location", target)
                self.end_headers()
                return
            if self.path == "/error":
                self.send_error(503, "private-response-sentinel")
                return
            self.send_response(200)
            self.end_headers()
            try:
                if self.path == "/stall":
                    time.sleep(1)
                elif self.path == "/slow":
                    for _ in range(8):
                        self.wfile.write(b"s")
                        self.wfile.flush()
                        time.sleep(0.08)
                else:
                    self.wfile.write(
                        b"a" * 11 if self.path == "/large" else b"verified"
                    )
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{server.server_port}", cert, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def trusted_server(tls_server, monkeypatch, tmp_path):
    url, cert, requests = tls_server
    monkeypatch.setenv("SSL_CERT_FILE", str(cert))
    monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
    monkeypatch.setattr(asset.tempfile, "tempdir", str(tmp_path))
    return url, requests


def test_native_socket_timeout_allows_progress_beyond_total_deadline(trusted_server):
    """Demonstrate old urllib semantics and corrected supervision on one server."""
    url, _ = trusted_server
    started = time.monotonic()
    with urllib.request.urlopen(f"{url}/slow", timeout=0.15) as response:
        assert response.read(9) == b"s" * 8
    old_elapsed = time.monotonic() - started
    assert old_elapsed > 0.5
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="total transfer deadline"):
        asset.download(f"{url}/slow", 9, timeout=0.3)
    new_elapsed = time.monotonic() - started
    assert 0.25 <= new_elapsed < 1.2
    print(f"native socket elapsed={old_elapsed:.3f}; total deadline={new_elapsed:.3f}")


def test_native_success_redirect_and_exact_byte_limit(trusted_server, tmp_path):
    url, requests = trusted_server
    assert asset.download(f"{url}/fast", 8, timeout=2) == b"verified"
    assert asset.download(f"{url}/redirect-safe", 8, timeout=2) == b"verified"
    assert "/redirect-safe" in requests
    assert not list(tmp_path.glob("asset-download-*"))


@pytest.mark.parametrize(
    "route,message",
    [
        ("large", "byte limit"),
        ("redirect-http", "HTTPS throughout redirects"),
        ("error", "failed during HTTPS transfer"),
        ("slow", "total transfer deadline"),
        ("stall", "total transfer deadline"),
        ("redirect-slow", "total transfer deadline"),
    ],
)
def test_native_failure_categories_cleanup_and_no_response_leak(
    trusted_server, tmp_path, route, message
):
    url, _ = trusted_server
    with pytest.raises((ValueError, TimeoutError), match=message) as failure:
        asset.download(f"{url}/{route}", 10, timeout=0.3)
    assert "private-response-sentinel" not in str(failure.value)
    assert not list(tmp_path.glob("asset-download-*"))


@pytest.mark.parametrize(
    "url", ["http://localhost", "file:///etc/passwd", "ftp://host"]
)
def test_protocol_rejected_without_subprocess(monkeypatch, url):
    def forbidden(*_args, **_kwargs):
        pytest.fail("unsupported protocol reached worker")

    monkeypatch.setattr(asset.subprocess, "run", forbidden)
    with pytest.raises(ValueError, match="HTTPS"):
        asset.download(url, 10)


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_deadline_fails_before_worker(timeout):
    with pytest.raises(ValueError, match="positive byte and time"):
        asset.download("https://github.com/official", 10, timeout)


@pytest.mark.parametrize("provisioner", ["provision_gitleaks", "provision_shfmt"])
def test_download_failure_preserves_existing_binary(
    trusted_server, monkeypatch, tmp_path, provisioner
):
    module = load_helper(provisioner)
    url, _ = trusted_server
    monkeypatch.setattr(
        module, "download", lambda *_: asset.download(f"{url}/slow", 9, timeout=0.3)
    )
    destination = tmp_path / "bin"
    destination.mkdir()
    binary = destination / provisioner.removeprefix("provision_")
    binary.write_bytes(b"previous verified executable")
    with pytest.raises(TimeoutError, match="total transfer deadline"):
        module.provision(destination)
    assert binary.read_bytes() == b"previous verified executable"
    assert list(destination.iterdir()) == [binary]


def test_gitleaks_corrupt_archive_rejected_before_any_write(monkeypatch, tmp_path):
    module = load_helper("provision_gitleaks")
    monkeypatch.setattr(module, "download", lambda *_: b"corrupt fixture")
    destination = tmp_path / "bin"
    with pytest.raises(ValueError, match="checksum"):
        module.provision(destination)
    assert not destination.exists()


def test_gitleaks_verifies_archive_before_extracting_and_executable_mode(
    monkeypatch, tmp_path
):
    module = load_helper("provision_gitleaks")
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w:gz") as archive:
        for name, content in [("gitleaks", b"binary fixture"), ("LICENSE", b"license")]:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    data = archive_bytes.getvalue()
    monkeypatch.setattr(module, "archive_name", lambda: "linux_x64")
    monkeypatch.setitem(module.ARCHIVES, "linux_x64", hashlib.sha256(data).hexdigest())
    monkeypatch.setattr(module, "download", lambda *_: data)
    module.provision(tmp_path)
    assert (tmp_path / "gitleaks").read_bytes() == b"binary fixture"
    assert (tmp_path / "gitleaks").stat().st_mode & 0o777 == 0o755
    assert (tmp_path / "GITLEAKS-LICENSE").read_bytes() == b"license"


@pytest.mark.parametrize("provisioner", ["provision_gitleaks", "provision_shfmt"])
@pytest.mark.parametrize("sibling", ["missing", "escaping-symlink"])
def test_isolated_provisioner_missing_owned_sibling_is_clear(
    tmp_path, provisioner, sibling
):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / f"{provisioner}.py"
    shutil.copyfile(ROOT / "scripts" / script.name, script)
    # A caller-controlled import candidate must never compensate for a missing sibling.
    sentinel = tmp_path / "executed"
    unowned = tmp_path / "download_asset.py"
    unowned.write_text(f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n")
    if sibling == "escaping-symlink":
        (scripts / "download_asset.py").symlink_to(unowned)
    result = subprocess.run(
        [sys.executable, "-I", str(script), str(tmp_path / "bin")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert (
        "verified sibling download_asset.py is missing or outside scripts"
        in result.stderr
    )
    assert "Traceback" not in result.stderr
    assert not sentinel.exists()
    assert not (tmp_path / "bin").exists()


@pytest.mark.parametrize("provisioner", ["provision_gitleaks", "provision_shfmt"])
def test_owned_sibling_loads_under_isolated_python(tmp_path, provisioner):
    script = ROOT / "scripts" / f"{provisioner}.py"
    program = (
        "import runpy; "
        f"module=runpy.run_path({str(script)!r}); "
        "helper=module['transfer_helper'](); "
        "assert helper.DEADLINE_SECONDS == 60; "
        "assert helper.__file__.endswith('/scripts/download_asset.py')"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", program],
        cwd=tmp_path,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr


def test_native_timeout_kills_and_reaps_worker(trusted_server, monkeypatch):
    url, _ = trusted_server
    processes = []
    original = subprocess.Popen

    class RecordedProcess(original):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            processes.append(self)

    monkeypatch.setattr(asset.subprocess, "Popen", RecordedProcess)
    with pytest.raises(TimeoutError, match="total transfer deadline"):
        asset.download(f"{url}/slow", 9, timeout=0.3)
    assert len(processes) == 1
    assert processes[0].returncode is not None
    assert processes[0].poll() is not None


def test_native_worker_ignores_caller_python_modules(
    trusted_server, monkeypatch, tmp_path
):
    url, _ = trusted_server
    sentinel = tmp_path / "executed"
    hostile = f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n"
    (tmp_path / "sitecustomize.py").write_text(hostile)
    (tmp_path / "urllib.py").write_text(hostile)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    assert asset.download(f"{url}/fast", 8, timeout=2) == b"verified"
    assert not sentinel.exists()
