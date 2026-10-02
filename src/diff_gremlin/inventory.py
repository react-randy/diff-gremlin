"""Inventory regular source files with explicit scope and resource coverage."""

import os
import stat
from dataclasses import asdict, dataclass, field
from itertools import islice
from pathlib import Path

from diff_gremlin.domain.context import SourceFile
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.sources import SourceScopeEntry
from diff_gremlin.domain.stages import StageResult
from diff_gremlin.source_paths import EXCLUDED_DIRECTORIES, in_scope
from diff_gremlin.source_scope import classify_content

MAX_FILES = 20000
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 100000
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
    scope_manifest: tuple[SourceScopeEntry, ...] = ()


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


@dataclass(slots=True)
class InventoryState:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    issues: list[Finding] = field(default_factory=list)
    exclusions: dict[str, int] = field(default_factory=dict)
    total: int = 0
    read_total: int = 0
    entries: int = 0
    capped: bool = False
    scope_manifest: list[SourceScopeEntry] = field(default_factory=list)
    manifest_paths: set[str] = field(default_factory=set)

    def issue(self, path: Path, reason: str, size: int = 0) -> None:
        relative = path.as_posix()
        self.issues.append(_issue(relative, reason))
        if relative not in self.manifest_paths:
            self.manifest_paths.add(relative)
            self.scope_manifest.append(
                SourceScopeEntry(relative, size, "possible-source", reason)
            )

    def limit_reached(self, relative: Path) -> bool:
        self.entries += 1
        if self.entries <= MAX_ENTRIES and len(self.files) < MAX_FILES:
            return False
        self.issue(relative, "Inventory entry/file limit reached")
        self.capped = True
        return True


def inventory_file(state: InventoryState, child, relative: Path, size: int) -> None:
    budget = MAX_TREE_BYTES - state.read_total
    if budget <= 0:
        state.issue(relative, "Inventory content read budget reached", size)
        return
    with open(child.path, "rb") as stream:
        content = stream.read(min(MAX_FILE_BYTES + 1, budget))
    state.read_total += len(content)
    classification, reason = classify_content(relative.as_posix(), content)
    if classification == "binary-asset":
        state.scope_manifest.append(
            SourceScopeEntry(relative.as_posix(), size, classification, reason)
        )
        state.manifest_paths.add(relative.as_posix())
        return
    if (
        size > MAX_FILE_BYTES
        or len(content) > MAX_FILE_BYTES
        or len(content) != size
        or state.total + size > MAX_TREE_BYTES
    ):
        state.issue(relative, "Inventory byte limit reached", size)
        return
    if classification == "possible-source":
        state.issue(relative, reason, size)
    state.total += size
    state.files.append(
        SourceFile(
            Path(child.path),
            relative.as_posix(),
            LANGUAGES.get(relative.suffix.lower(), ""),
            is_test_path(relative),
            size,
            classification,
        )
    )


def inventory_entry(
    state: InventoryState, child, relative: Path, pending: list[Path]
) -> None:
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


def inventory_directory(
    state: InventoryState, directory: Path, pending: list[Path]
) -> None:
    try:
        with os.scandir(directory) as children:
            bounded = islice(children, max(1, MAX_ENTRIES - state.entries + 1))
            for child in sorted(bounded, key=lambda child: child.name):
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
    present = {file.relative_path for file in state.files}
    return StageResult(
        "inventory",
        "Source inventory",
        "hygiene",
        "limited" if state.issues else "ok",
        "builtin",
        metrics={
            "files": len(state.files),
            "text_files": sum(f.classification == "text" for f in state.files),
            "binary_asset_files": sum(
                row.classification == "binary-asset" for row in state.scope_manifest
            ),
            "omitted_possible_source_files": sum(
                row.classification == "possible-source" for row in state.scope_manifest
            ),
            "scope_manifest": [
                asdict(row)
                for row in sorted(
                    state.scope_manifest, key=lambda row: row.relative_path
                )
            ],
            "text_scope": "UTF-8 without NUL; signature-identified binary assets excluded; archives, embedded content and alternate encodings not analyzed",
            "bytes": state.total,
            "content_bytes_read": state.read_total,
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
        eligible_files=len(state.files)
        + sum(
            row.classification == "possible-source" and row.relative_path not in present
            for row in state.scope_manifest
        ),
    )


def _inventory_state(
    root: Path, scope_manifest: tuple[SourceScopeEntry, ...]
) -> InventoryState:
    """Merge captured omissions into the initial inventory coverage state."""
    scope_manifest = tuple(row for row in scope_manifest if in_scope(row.relative_path))
    state = InventoryState(
        root,
        scope_manifest=list(scope_manifest),
        manifest_paths={row.relative_path for row in scope_manifest},
    )
    for row in scope_manifest:
        if row.classification != "binary-asset":
            state.issue(Path(row.relative_path), row.reason)
    return state


def _inventory_result(state: InventoryState) -> Inventory:
    """Freeze collected state into deterministic analyzer inputs and coverage."""
    state.files.sort(key=lambda source: source.relative_path)
    return Inventory(
        tuple(state.files),
        tuple(f for f in state.files if f.language and not f.is_test),
        tuple(sorted({f.language for f in state.files if f.language})),
        inventory_stage(state),
        tuple(sorted(state.scope_manifest, key=lambda row: row.relative_path)),
    )


def collect_inventory(
    root: Path, scope_manifest: tuple[SourceScopeEntry, ...] = ()
) -> Inventory:
    """Count regular in-scope files without traversing a symbolic link."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Inventory root must be a regular directory")
    state = _inventory_state(root, scope_manifest)
    pending = [root]
    while pending and not state.capped:
        inventory_directory(state, pending.pop(), pending)
    return _inventory_result(state)
