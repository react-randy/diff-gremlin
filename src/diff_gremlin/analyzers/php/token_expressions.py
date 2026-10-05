"""Extract bounded argument and statement slices from PHP parser tokens."""

from diff_gremlin.analyzers.php.token_model import PHPToken

_IGNORED = {
    "T_WHITESPACE",
    "T_COMMENT",
    "T_DOC_COMMENT",
    "T_OPEN_TAG",
    "T_CLOSE_TAG",
    "T_INLINE_HTML",
}


def significant(tokens: tuple[PHPToken, ...]) -> tuple[PHPToken, ...]:
    return tuple(token for token in tokens if token.kind not in _IGNORED)


def arguments(
    tokens: tuple[PHPToken, ...], index: int
) -> tuple[tuple[PHPToken, ...], ...]:
    if index >= len(tokens) or tokens[index].text != "(":
        return ()
    depth = 0
    start = index + 1
    result = []
    for cursor in range(index, len(tokens)):
        text = tokens[cursor].text
        if text in {"(", "[", "{"}:
            depth += 1
        elif text in {")", "]", "}"}:
            depth -= 1
            if depth == 0:
                result.append(tokens[start:cursor])
                return tuple(result)
        elif text == "," and depth == 1:
            result.append(tokens[start:cursor])
            start = cursor + 1
    return ()


def statement(tokens: tuple[PHPToken, ...], index: int) -> tuple[PHPToken, ...]:
    for cursor in range(index, len(tokens)):
        if tokens[cursor].text == ";":
            return tokens[index:cursor]
    return tokens[index:]


def global_call(tokens: tuple[PHPToken, ...], index: int) -> bool:
    if index and tokens[index - 1].text in {"->", "?->", "::", "function", "new"}:
        return False
    return index + 1 < len(tokens) and tokens[index + 1].text == "("
