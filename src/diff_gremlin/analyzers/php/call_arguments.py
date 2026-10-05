"""Resolve PHP builtin positional/named argument expressions from parser tokens."""

from diff_gremlin.analyzers.php.token_model import PHPToken


def named_argument(tokens: tuple[PHPToken, ...]) -> str | None:
    """An argument label is metadata, not part of its evaluated expression."""
    if len(tokens) >= 2 and tokens[0].kind == "T_STRING" and tokens[1].text == ":":
        return tokens[0].text
    return None


def builtin_argument(
    args: tuple[tuple[PHPToken, ...], ...], position: int, name: str
) -> tuple[PHPToken, ...]:
    """Respect native signature names, including reordered PHP 8 arguments."""
    positional = []
    for tokens in args:
        label = named_argument(tokens)
        if label == name:
            return tokens[2:]
        if label is None:
            positional.append(tokens)
    return positional[position] if position < len(positional) else ()
