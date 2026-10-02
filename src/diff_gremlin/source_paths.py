"""One directory exclusion policy for acquisition, identity, and inventory."""

from pathlib import PurePosixPath

EXCLUDED_DIRECTORIES = {
    ".git": "Git metadata is inspected separately",
    "node_modules": "installed dependencies",
    "vendor": "vendored dependencies",
    ".venv": "Python environment",
    "venv": "Python environment",
    "__pycache__": "Python bytecode",
    ".mypy_cache": "type-check cache",
    ".pytest_cache": "test cache",
    ".ruff_cache": "lint cache",
    ".pyscn": "analyzer artifacts",
    ".wily": "history cache",
    "target": "Rust/build artifacts",
    "build": "build artifacts",
    "dist": "distribution artifacts",
    ".next": "framework build artifacts",
    ".gradle": "Gradle cache",
    ".idea": "editor metadata",
}


def in_scope(path: str) -> bool:
    """Exclude directory contents while retaining same-named regular files."""
    return not any(
        part in EXCLUDED_DIRECTORIES for part in PurePosixPath(path).parts[:-1]
    )
