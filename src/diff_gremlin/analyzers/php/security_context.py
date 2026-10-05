"""Recognize local lexical request and escaping context without claiming flow."""

from diff_gremlin.analyzers.php.token_expressions import arguments, statement
from diff_gremlin.analyzers.php.token_model import PHPToken

_REQUEST = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER"}


def request_context(tokens: tuple[PHPToken, ...], aliases: set[str]) -> bool:
    return any(
        (token.text in _REQUEST or token.text in aliases)
        or (
            token.kind == "T_STRING"
            and token.text.lower() in {"request", "input", "filter_input"}
        )
        for token in tokens
    )


def request_aliases(tokens: tuple[PHPToken, ...]) -> set[str]:
    aliases: set[str] = set()
    cursor = 0
    while cursor + 1 < len(tokens):
        token = tokens[cursor]
        if token.kind == "T_VARIABLE" and tokens[cursor + 1].text == "=":
            expression = statement(tokens, cursor + 2)
            if request_context(expression, aliases):
                aliases.add(token.text)
            cursor += len(expression) + 2
        else:
            cursor += 1
    return aliases


def _array_content(tokens: tuple[PHPToken, ...]) -> tuple[PHPToken, ...]:
    if tokens and tokens[0].text == "[" and tokens[-1].text == "]":
        return tokens[1:-1]
    elif (
        len(tokens) >= 3
        and tokens[0].text.lower() == "array"
        and tokens[1].text == "("
        and tokens[-1].text == ")"
    ):
        return tokens[2:-1]
    return ()


def allowed_unserialize(tokens: tuple[PHPToken, ...]) -> bool:
    # Recognize exactly one literal option. Duplicate keys or dynamic options
    # can change the effective value and must not suppress an observation.
    content = _array_content(tokens)
    if content and content[-1].text == ",":
        content = content[:-1]
    return (
        len(content) == 3
        and content[0].kind == "T_CONSTANT_ENCAPSED_STRING"
        and content[0].text[1:-1] == "allowed_classes"
        and content[1].text == "=>"
        and content[2].text.lower() == "false"
    )


def _escaped_argument_end(tokens: tuple[PHPToken, ...], cursor: int) -> int:
    token = tokens[cursor]
    if (
        token.kind not in {"T_STRING", "T_NAME_FULLY_QUALIFIED"}
        or token.text.lower().lstrip("\\") != "escapeshellarg"
        or not arguments(tokens, cursor + 1)
    ):
        return cursor
    depth = 0
    for index in range(cursor + 1, len(tokens)):
        depth += tokens[index].text == "("
        depth -= tokens[index].text == ")"
        if depth == 0:
            return index + 1
    return cursor


def dynamic_shell(tokens: tuple[PHPToken, ...]) -> bool:
    # Literal command text plus explicit escapeshellarg calls is a benign control.
    cursor = 0
    while cursor < len(tokens):
        escaped_end = _escaped_argument_end(tokens, cursor)
        if escaped_end > cursor:
            cursor = escaped_end
            continue
        token = tokens[cursor]
        if token.kind in {
            "T_VARIABLE",
            "T_STRING_VARNAME",
            "T_DOLLAR_OPEN_CURLY_BRACES",
            "T_CURLY_OPEN",
        }:
            return True
        if token.kind in {"T_STRING", "T_NAME_FULLY_QUALIFIED", "T_NAME_QUALIFIED"}:
            return True
        cursor += 1
    return False
