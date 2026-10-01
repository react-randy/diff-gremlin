"""Locate selected Unicode controls while allowing ordinary Unicode text."""

import unicodedata

from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.findings import Finding
from diff_gremlin.domain.stages import StageResult

_BIDI = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
_HIDDEN = {0x180E, 0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064}


def _legitimate_joiner(text: str, index: int) -> bool:
    if not 0 < index < len(text) - 1:
        return False
    before, after = text[index - 1], text[index + 1]
    emoji = lambda char: ord(char) >= 0x1F000 or ord(char) in {0xFE0F, 0x2764}
    letters = lambda char: (
        ord(char) > 127 and unicodedata.category(char).startswith(("L", "M"))
    )
    return (emoji(before) and emoji(after)) or (letters(before) and letters(after))


def _control_rule(text: str, index: int) -> tuple[str, str] | None:
    code = ord(text[index])
    if code in _BIDI:
        return "unicode.bidi-control", "high" if code in {0x202D, 0x202E} else "medium"
    if 0xE0001 <= code <= 0xE007F and not any(
        ord(char) >= 0x1F000 and ord(char) < 0xE0000
        for char in text[max(0, index - 12) : index]
    ):
        return "unicode.unexpected-tag", "low"
    if code == 0x00AD:
        return "unicode.soft-hyphen", "info"
    if code in _HIDDEN:
        return "unicode.invisible-control", "low"
    if code in {0x200C, 0x200D} and not _legitimate_joiner(text, index):
        return "unicode.unexpected-joiner", "low"
    if code == 0xFEFF and index != 0:
        return "unicode.misplaced-bom", "low"
    if (0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF) and (
        index == 0 or ord(text[index - 1]) < 128
    ):
        return "unicode.unexpected-variation-selector", "low"
    return None


def analyze_unicode(ctx: ScanContext) -> StageResult:
    findings, skipped = [], []
    analyzed = 0
    for file in ctx.files:
        if file.size_bytes > 1024 * 1024:
            skipped.append(file.relative_path)
            continue
        try:
            text = file.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            skipped.append(file.relative_path)
            continue
        if "\x00" in text:
            skipped.append(file.relative_path)
            continue
        analyzed += 1
        line, column = 1, 1
        for index, char in enumerate(text):
            rule = _control_rule(text, index)
            if rule:
                name, severity = rule
                findings.append(
                    Finding(
                        name,
                        f"U+{ord(char):04X} {unicodedata.name(char, 'CONTROL')}; review text direction/context",
                        severity,
                        file.relative_path,
                        line,
                        column,
                        symbol=f"U+{ord(char):04X}",
                    )
                )
            if char == "\n":
                line, column = line + 1, 1
            else:
                column += 1
    return StageResult(
        "security.unicode",
        "Unicode control observations",
        "security",
        "limited" if skipped else "ok",
        "builtin-unicode",
        unicodedata.unidata_version,
        metrics={"control_count": len(findings), "skipped_paths": skipped},
        findings=findings,
        reason="Selected control characters in current UTF-8 text; Unicode text is not itself suspicious"
        + ("; unreadable/binary/large files omitted" if skipped else ""),
        scope="current-inventoried-text",
        analyzed_files=analyzed,
        eligible_files=len(ctx.files),
    )
