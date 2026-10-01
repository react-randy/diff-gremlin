"""Read Git blob batches against captured tree metadata."""

from collections.abc import Iterator
from pathlib import Path

from diff_gremlin.acquisition.git import Git
from diff_gremlin.acquisition.tree import TreeEntry


def _batches(entries: tuple[TreeEntry, ...]) -> Iterator[list[TreeEntry]]:
    offset = 0
    while offset < len(entries):
        batch = []
        size = 0
        while offset < len(entries) and (not batch or size < 1024 * 1024):
            entry = entries[offset]
            batch.append(entry)
            size += entry.size
            offset += 1
        yield batch


def _decode_batch(output: bytes, batch: list[TreeEntry]) -> Iterator[tuple[TreeEntry, bytes]]:
    cursor = 0
    for entry in batch:
        end = output.find(b"\n", cursor)
        if end < 0:
            raise RuntimeError("Git blob batch has an incomplete object header")
        header = output[cursor:end].decode().split()
        if header != [entry.oid, "blob", str(entry.size)]:
            raise RuntimeError("Git blob batch differs from the captured tree metadata")
        cursor = end + 1
        content = output[cursor : cursor + entry.size]
        cursor += entry.size
        if len(content) != entry.size or output[cursor : cursor + 1] != b"\n":
            raise RuntimeError("Git blob batch has an incomplete object body")
        cursor += 1
        yield entry, content
    if cursor != len(output):
        raise RuntimeError("Git blob batch contains unexpected trailing data")


def blob_batches(
    git: Git, repo: Path, entries: tuple[TreeEntry, ...]
) -> Iterator[tuple[TreeEntry, bytes]]:
    for batch in _batches(entries):
        size = sum(entry.size for entry in batch)
        text = git.run(
            ["cat-file", "--batch"],
            cwd=repo,
            data=True,
            input_text="".join(f"{entry.oid}\n" for entry in batch),
            limit=size + len(batch) * 128 + 1,
        )
        yield from _decode_batch(text.encode("utf-8", "surrogateescape"), batch)
