"""Inventory regular source files with explicit scope and resource coverage."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from diff_gremlin.domain.context import SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

MAX_FILES = 20000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 100000
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
LANGUAGES = {
    ".py": "python",
    ".pyi": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".rs": "rust",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".swift": "swift",
    ".m": "objc",
    ".mm": "objc",
    ".scala": "scala",
    ".lua": "lua",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".php": "php",
    ".sh": "shell",
}


@dataclass(frozen=True, slots=True)
class Inventory:
    files: tuple[SourceFile, ...]
    production_files: tuple[SourceFile, ...]
    languages: tuple[str, ...]
    stage: StageResult


def is_test_path(path: Path) -> bool:
    stem = path.stem
    return (
        any(
            part.lower() in {"test", "tests", "__tests__", "spec", "specs"}
            for part in path.parts
        )
        or stem.lower() == "test"
        or stem.lower().startswith("test_")
        or stem.lower().endswith(("_test", ".test", ".spec", "_spec"))
        or stem.endswith(("Test", "Tests"))
    )


def _issue(path: str, reason: str) -> Finding:
    return Finding("inventory.incomplete", reason, "info", path=path)


def collect_inventory(root: Path) -> Inventory:
    """Count all regular in-scope files without traversing a symbolic link."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Inventory root must be a regular directory")
    files = []
    issues = []
    exclusions: dict[str, int] = {}
    total = entries = 0
    pending = [root]
    capped = False
    while pending and not capped:
        directory = pending.pop()
        try:
            with os.scandir(directory) as children:
                for child in children:
                    entries += 1
                    relative = Path(child.path).relative_to(root)
                    if entries > MAX_ENTRIES or len(files) >= MAX_FILES:
                        issues.append(
                            _issue(
                                relative.as_posix(),
                                "Inventory entry/file limit reached",
                            )
                        )
                        capped = True
                        break
                    try:
                        info = child.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode):
                            issues.append(
                                _issue(
                                    relative.as_posix(), "Symbolic link not followed"
                                )
                            )
                        elif stat.S_ISDIR(info.st_mode):
                            if child.name in EXCLUDED_DIRECTORIES:
                                exclusions[child.name] = (
                                    exclusions.get(child.name, 0) + 1
                                )
                            else:
                                pending.append(Path(child.path))
                        elif stat.S_ISREG(info.st_mode):
                            if (
                                info.st_size > MAX_FILE_BYTES
                                or total + info.st_size > MAX_TREE_BYTES
                            ):
                                issues.append(
                                    _issue(
                                        relative.as_posix(),
                                        "Inventory byte limit reached",
                                    )
                                )
                                continue
                            # Check readability without loading a potentially large file.
                            with open(child.path, "rb") as stream:
                                stream.read(1)
                            total += info.st_size
                            files.append(
                                SourceFile(
                                    Path(child.path),
                                    relative.as_posix(),
                                    LANGUAGES.get(relative.suffix.lower(), ""),
                                    is_test_path(relative),
                                    info.st_size,
                                )
                            )
                        else:
                            issues.append(
                                _issue(relative.as_posix(), "Nonregular file not read")
                            )
                    except OSError:
                        issues.append(
                            _issue(
                                relative.as_posix(), "File metadata/content unreadable"
                            )
                        )
        except OSError:
            issues.append(
                _issue(directory.relative_to(root).as_posix(), "Directory unreadable")
            )
    files.sort(key=lambda source: source.relative_path)
    stage = StageResult(
        "inventory",
        "Source inventory",
        "hygiene",
        "limited" if issues else "ok",
        "builtin",
        metrics={
            "files": len(files),
            "bytes": total,
            "entries": entries,
            "excluded_directories": exclusions,
            "exclusion_reasons": EXCLUDED_DIRECTORIES.copy(),
            "max_files": MAX_FILES,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_tree_bytes": MAX_TREE_BYTES,
            "max_entries": MAX_ENTRIES,
        },
        findings=issues,
        reason="Some source paths were not inventoried" if issues else "",
        scope="all",
        analyzed_files=len(files),
        eligible_files=len(files) + len(issues),
    )
    return Inventory(
        tuple(files),
        tuple(f for f in files if f.language and not f.is_test),
        tuple(sorted({f.language for f in files if f.language})),
        stage,
    )
