"""Neutralize source-controlled terminal and Markdown formatting."""

import unicodedata


def plain(value: object) -> str:
    text = str(value)
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char
        for char in text
    )


def markdown(value: object) -> str:
    text = plain(value)
    for char in ("\\", "`", "*", "_", "[", "]", "<", ">", "|"):
        text = text.replace(char, "\\" + char)
    return text
