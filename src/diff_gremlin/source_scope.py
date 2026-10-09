"""Classify bounded content for text analysis without trusting filenames.

Archives are never expanded. Recognized binary containers are outside current
text analysis; embedded/archive/polyglot content is not certified. Unknown bytes
and binary content under source filenames remain possible-source limitations.
"""

from pathlib import PurePosixPath

SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".java",
        ".rs",
        ".go",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cxx",
        ".hpp",
        ".rb",
        ".swift",
        ".m",
        ".mm",
        ".scala",
        ".lua",
        ".kt",
        ".kts",
        ".cs",
        ".php",
        ".sh",
        ".json",
        ".toml",
        ".yaml",
        ".yml",
        ".xml",
        ".html",
        ".css",
        ".sql",
        ".md",
        ".txt",
        ".ini",
        ".cfg",
        ".env",
    }
)
SIGNATURES = (
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive"),
    (b"\x1f\x8b\x08", "gzip archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"\x7fELF", "ELF executable"),
    (b"\x00asm\x01\x00\x00\x00", "WebAssembly binary"),
    (b"wOFF", "WOFF font"),
    (b"wOF2", "WOFF2 font"),
    (b"\x00\x01\x00\x00", "TrueType font"),
    (b"OTTO", "OpenType font"),
    (b"BZh", "bzip2 archive"),
    (b"\xfd7zXZ\x00", "XZ archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"%PDF-1.", "PDF document"),
    (b"%PDF-2.", "PDF document"),
)


def _is_text(content: bytes) -> bool:
    """Recognize UTF-8 without embedded binary NUL bytes."""
    try:
        content.decode("utf-8")
        return b"\x00" not in content
    except UnicodeError:
        return False


def _media_container(content: bytes) -> str:
    """Recognize bounded RIFF and ISO media headers from captured bytes."""
    if (
        len(content) >= 12
        and content[:4] == b"RIFF"
        and content[8:12] in {b"WEBP", b"WAVE", b"AVI "}
    ):
        return "RIFF media container; contents not expanded or analyzed"
    if (
        len(content) >= 16
        and content[4:8] == b"ftyp"
        and 16 <= int.from_bytes(content[:4], "big") <= len(content)
        and content[8:12]
        in {b"isom", b"iso2", b"mp41", b"mp42", b"M4V ", b"qt  ", b"avif", b"avis"}
    ):
        return "ISO base media container; contents not expanded or analyzed"
    return ""


def _icon_image(content: bytes, width: int, height: int) -> bool:
    """Validate a PNG header or the complete minimum uncompressed icon bitmap."""
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return (
            len(content) >= 33
            and content[8:16] == b"\x00\x00\x00\rIHDR"
            and int.from_bytes(content[16:20], "big") == width
            and int.from_bytes(content[20:24], "big") == height
            and content.endswith(b"\x00\x00\x00\x00IEND\xaeB`\x82")
        )
    if len(content) < 40:
        return False
    header = int.from_bytes(content[:4], "little")
    bits = int.from_bytes(content[14:16], "little")
    colors = int.from_bytes(content[32:36], "little")
    if (
        header not in {40, 108, 124}
        or len(content) < header
        or int.from_bytes(content[4:8], "little", signed=True) != width
        or int.from_bytes(content[8:12], "little", signed=True) != height * 2
        or content[12:14] != b"\x01\x00"
        or bits not in {1, 4, 8, 16, 24, 32}
        or content[16:20] != b"\x00\x00\x00\x00"
        or colors > (1 << bits if bits <= 8 else 0)
    ):
        return False
    palette = (colors or 1 << bits) * 4 if bits <= 8 else 0
    pixels = ((width * bits + 31) // 32) * 4 * height
    mask = ((width + 31) // 32) * 4 * height
    return len(content) == header + palette + pixels + mask


def _icon_container(content: bytes) -> bool:
    """Require a complete ICO directory and recognized, bounded image payloads."""
    if len(content) < 6 or content[:4] != b"\x00\x00\x01\x00":
        return False
    count = int.from_bytes(content[4:6], "little")
    boundary = 6 + 16 * count
    if not count or count > 256 or boundary > len(content):
        return False
    ranges = []
    for index in range(count):
        entry = content[6 + 16 * index : 22 + 16 * index]
        size = int.from_bytes(entry[8:12], "little")
        start = int.from_bytes(entry[12:16], "little")
        end = start + size
        if (
            entry[3] != 0
            or not size
            or start < boundary
            or end > len(content)
            or not _icon_image(content[start:end], entry[0] or 256, entry[1] or 256)
        ):
            return False
        ranges.append((start, end))
    for start, end in sorted(ranges):
        if start != boundary:
            return False
        boundary = end
    return boundary == len(content)


def classify_content(path: str, content: bytes) -> tuple[str, str]:
    """Return text, binary-asset, or possible-source from content evidence."""
    if _is_text(content):
        return "text", "UTF-8 text"
    if PurePosixPath(path).suffix.lower() in SOURCE_SUFFIXES:
        return "possible-source", "Source/text filename contains non-UTF-8 or NUL bytes"
    if _icon_container(content):
        return "binary-asset", "ICO image; contents not expanded or analyzed"
    if reason := _media_container(content):
        return "binary-asset", reason
    for signature, kind in SIGNATURES:
        if content.startswith(signature):
            return "binary-asset", kind + "; contents not expanded or analyzed"
    return "possible-source", "Unrecognized non-UTF-8 or NUL content"
