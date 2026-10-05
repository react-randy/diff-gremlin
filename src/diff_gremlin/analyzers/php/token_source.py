"""Read only bounded source bytes matching the captured inventory size."""

from pathlib import Path

from diff_gremlin.domain.context import ScanContext, SourceFile

MAX_SOURCE = 8 * 1024 * 1024


def source_path(ctx: ScanContext, file: SourceFile) -> Path:
    relative = Path(file.relative_path)
    resolved = file.path.resolve(strict=True)
    if (
        relative.is_absolute()
        or ".." in relative.parts
        or file.path.is_symlink()
        or not resolved.is_relative_to(ctx.root.resolve())
        or (ctx.root / relative).resolve() != resolved
        or not resolved.is_file()
    ):
        raise ValueError("source outside regular inventory")
    return resolved


def read_source(ctx: ScanContext, file: SourceFile) -> bytes:
    if not 0 <= file.size_bytes <= MAX_SOURCE:
        raise ValueError("source inventory exceeds byte budget")
    resolved = source_path(ctx, file)
    # Bound the actual read, including when the file grows after inventory/stat.
    with resolved.open("rb") as stream:
        source = stream.read(MAX_SOURCE + 1)
    if len(source) > MAX_SOURCE:
        raise ValueError("source exceeds byte budget")
    if len(source) != file.size_bytes:
        raise ValueError("source size differs from captured inventory")
    return source
