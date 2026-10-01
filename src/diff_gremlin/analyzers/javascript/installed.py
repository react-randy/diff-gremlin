"""Resolve installed Node packages without consulting a source checkout."""

import json
import shutil
from pathlib import Path

from diff_gremlin.domain.context import ScanContext
from diff_gremlin.process import trusted_path


def trusted_executable(ctx: ScanContext, name: str) -> str | None:
    """Discover executables only in the shared trusted installed-tool search path."""
    candidate = shutil.which(name, path=trusted_path(ctx.root))
    if not candidate:
        return None
    path = Path(candidate).resolve()
    if path.is_relative_to(ctx.root.resolve()):
        return None
    return str(path)


def installed_package(ctx: ScanContext, executable: str, package: str) -> Path | None:
    """Locate an exact package via its installed binary, never target resolution."""
    binary = trusted_executable(ctx, executable)
    if not binary:
        return None
    for parent in Path(binary).parents:
        manifest = parent / "package.json"
        if not manifest.is_file():
            continue
        try:
            metadata = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(metadata, dict) and metadata.get("name") == package:
            return parent
    return None


def package_version(package: Path) -> str:
    """Read the controlled installed package version."""
    metadata = json.loads((package / "package.json").read_text(encoding="utf-8"))
    version = metadata.get("version", "")
    return version if isinstance(version, str) else ""


def sibling_package(package: Path, name: str) -> Path | None:
    """Find a dependency only inside the selected installed tool environment."""
    for parent in package.parents:
        if parent.name == "node_modules":
            candidate = parent / name
            return candidate.resolve() if (candidate / "package.json").is_file() else None
    return None
