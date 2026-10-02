"""Read current text with the same finite bound as source inventory."""

from diff_gremlin.inventory import MAX_FILE_BYTES


def read_text(file):
    if file.classification != "text" or file.size_bytes > MAX_FILE_BYTES:
        raise ValueError("File is outside bounded current text scope")
    with file.path.open("rb") as stream:
        content = stream.read(MAX_FILE_BYTES + 1)
    if len(content) > MAX_FILE_BYTES or b"\x00" in content:
        raise ValueError("Content exceeds text budget or contains NUL")
    return content.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def omitted_paths(ctx):
    """Count only declared possible source absent from the file inventory."""
    present = {file.relative_path for file in ctx.files}
    return [
        row.relative_path
        for row in ctx.scope_manifest
        if row.classification != "binary-asset" and row.relative_path not in present
    ]
