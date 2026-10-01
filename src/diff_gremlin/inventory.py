"""Inventory regular source files with explicit scope and resource coverage."""

import os
import stat
from dataclasses import dataclass, field
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
        any(part.lower() in {"test", "tests", "__tests__", "spec", "specs"} for part in path.parts)
        or stem.lower() == "test"
        or stem.lower().startswith("test_")
        or stem.lower().endswith(("_test", ".test", ".spec", "_spec"))
        or stem.endswith(("Test", "Tests"))
    )


def _issue(path: str, reason: str) -> Finding:
    return Finding("inventory.incomplete", reason, "info", path=path)


@dataclass(slots=True)
class InventoryState:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    issues: list[Finding] = field(default_factory=list)
    exclusions: dict[str, int] = field(default_factory=dict)
    total: int = 0
    entries: int = 0
    capped: bool = False

    def issue(self, path: Path, reason: str) -> None:
        self.issues.append(_issue(path.as_posix(), reason))

    def limit_reached(self, relative: Path) -> bool:
        self.entries += 1
        if self.entries <= MAX_ENTRIES and len(self.files) < MAX_FILES:
            return False
        self.issue(relative, "Inventory entry/file limit reached")
        self.capped = True
        return True


def inventory_file(state: InventoryState, child, relative: Path, size: int) -> None:
    if size > MAX_FILE_BYTES or state.total + size > MAX_TREE_BYTES:
        state.issue(relative, "Inventory byte limit reached")
        return
    with open(child.path, "rb") as stream:
        stream.read(1)
    state.total += size
    state.files.append(
        SourceFile(
            Path(child.path),
            relative.as_posix(),
            LANGUAGES.get(relative.suffix.lower(), ""),
            is_test_path(relative),
            size,
        )
    )


def inventory_entry(state: InventoryState, child, relative: Path, pending: list[Path]) -> None:
    info = child.stat(follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode):
        state.issue(relative, "Symbolic link not followed")
    elif stat.S_ISDIR(info.st_mode):
        if child.name in EXCLUDED_DIRECTORIES:
            state.exclusions[child.name] = state.exclusions.get(child.name, 0) + 1
        else:
            pending.append(Path(child.path))
    elif stat.S_ISREG(info.st_mode):
        inventory_file(state, child, relative, info.st_size)
    else:
        state.issue(relative, "Nonregular file not read")


def inventory_directory(state: InventoryState, directory: Path, pending: list[Path]) -> None:
    try:
        with os.scandir(directory) as children:
            for child in children:
                relative = Path(child.path).relative_to(state.root)
                if state.limit_reached(relative):
                    break
                try:
                    inventory_entry(state, child, relative, pending)
                except OSError:
                    state.issue(relative, "File metadata/content unreadable")
    except OSError:
        state.issue(directory.relative_to(state.root), "Directory unreadable")


def inventory_stage(state: InventoryState) -> StageResult:
    return StageResult(
        "inventory",
        "Source inventory",
        "hygiene",
        "limited" if state.issues else "ok",
        "builtin",
        metrics={
            "files": len(state.files),
            "bytes": state.total,
            "entries": state.entries,
            "excluded_directories": state.exclusions,
            "exclusion_reasons": EXCLUDED_DIRECTORIES.copy(),
            "max_files": MAX_FILES,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_tree_bytes": MAX_TREE_BYTES,
            "max_entries": MAX_ENTRIES,
        },
        findings=state.issues,
        reason="Some source paths were not inventoried" if state.issues else "",
        scope="all",
        analyzed_files=len(state.files),
        eligible_files=len(state.files) + len(state.issues),
    )


def collect_inventory(root: Path) -> Inventory:
    """Count regular in-scope files without traversing a symbolic link."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Inventory root must be a regular directory")
    state = InventoryState(root)
    pending = [root]
    while pending and not state.capped:
        inventory_directory(state, pending.pop(), pending)
    state.files.sort(key=lambda source: source.relative_path)
    return Inventory(
        tuple(state.files),
        tuple(f for f in state.files if f.language and not f.is_test),
        tuple(sorted({f.language for f in state.files if f.language})),
        inventory_stage(state),
    )
