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


def classify_content(path: str, content: bytes) -> tuple[str, str]:
    """Return text, binary-asset, or possible-source from content evidence."""
    try:
        content.decode("utf-8")
        text = b"\x00" not in content
    except UnicodeError:
        text = False
    if text:
        return "text", "UTF-8 text"
    if PurePosixPath(path).suffix.lower() in SOURCE_SUFFIXES:
        return "possible-source", "Source/text filename contains non-UTF-8 or NUL bytes"
    if (
        len(content) >= 12
        and content[:4] == b"RIFF"
        and content[8:12] in {b"WEBP", b"WAVE", b"AVI "}
    ):
        return "binary-asset", "RIFF media container; contents not expanded or analyzed"
    if (
        len(content) >= 16
        and content[4:8] == b"ftyp"
        and 16 <= int.from_bytes(content[:4], "big") <= len(content)
        and content[8:12]
        in {b"isom", b"iso2", b"mp41", b"mp42", b"M4V ", b"qt  ", b"avif", b"avis"}
    ):
        return (
            "binary-asset",
            "ISO base media container; contents not expanded or analyzed",
        )
    for signature, kind in SIGNATURES:
        if content.startswith(signature):
            return "binary-asset", kind + "; contents not expanded or analyzed"
    return "possible-source", "Unrecognized non-UTF-8 or NUL content"
