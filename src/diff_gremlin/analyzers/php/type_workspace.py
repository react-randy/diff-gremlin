"""Build an owned PHPStan view without target configuration or autoloaders."""

import hashlib
import json
from pathlib import Path

from diff_gremlin.analyzers.php.type_identity import BYTES, LEVEL, SHA256
from diff_gremlin.domain.context import SourceFile


def isolated_phar(installed: Path, workspace: Path) -> Path:
    """Require reviewed bytes and contain PHPStan's ancestor-autoload probe."""
    with installed.open("rb") as stream:
        data = stream.read(BYTES + 1)
    if len(data) != BYTES or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("Installed PHPStan PHAR does not match reviewed 2.2.15 bytes")
    path = workspace / "tools" / "phpstan" / "bin" / "phpstan.phar"
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    return path


def source_view(
    files: tuple[SourceFile, ...], workspace: Path
) -> dict[Path, SourceFile]:
    """Copy only explicit PHP inputs into neutral paths, preserving diagnostic lines."""
    root = workspace / "source"
    root.mkdir()
    locations = {}
    for index, file in enumerate(files):
        path = root / f"{index}.php"
        if file.path.stat().st_size != file.size_bytes:
            raise ValueError("PHP source size differs from captured inventory")
        with file.path.open("rb") as stream:
            data = stream.read(file.size_bytes + 1)
        if len(data) != file.size_bytes:
            raise ValueError("PHP source read size differs from captured inventory")
        path.write_bytes(data)
        if path.stat().st_size != file.size_bytes:
            raise ValueError("PHP copied source size differs from captured inventory")
        locations[path] = file
    return locations


def configuration(workspace: Path, paths: tuple[Path, ...]) -> Path:
    """Select explicit paths, level and process limits; exclude every target config."""
    config = workspace / "phpstan.neon"
    rows = ["parameters:", f"    level: {LEVEL}", "    paths:"]
    rows.extend("        - " + json.dumps(str(path)) for path in paths)
    rows.extend(
        [
            "    tmpDir: " + json.dumps(str(workspace / "cache")),
            "    bootstrapFiles: []",
            "    scanFiles: []",
            "    scanDirectories: []",
            "    excludePaths: []",
            "    ignoreErrors: []",
            "    parallel:",
            "        maximumNumberOfProcesses: 1",
            "    tips:",
            "        discoveringSymbols: false",
        ]
    )
    config.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return config
