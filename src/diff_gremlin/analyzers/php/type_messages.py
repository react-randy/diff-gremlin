"""Reconstruct bounded PHPStan context without arbitrary native source text."""

import re

from diff_gremlin.runtime.environment import redact

_NAME = r"[A-Za-z_][A-Za-z0-9_]*(?:\\[A-Za-z_][A-Za-z0-9_]*)*"
_MEMBER = _NAME + r"::(?:\$?[A-Za-z_][A-Za-z0-9_]*)(?:\(\))?"
_TYPE = r"\??" + _NAME + r"(?:\[\])*(?:[|&]\??" + _NAME + r"(?:\[\])*)*"
_CREDENTIAL_PREFIX = re.compile(
    r"(?:\b|_)(?:gh[pousr]_|github_pat_|sk[-_]|AKIA)", re.IGNORECASE
)
_TEMPLATES = tuple(
    re.compile(pattern + r"\Z")
    for pattern in (
        rf"(?:Method {_MEMBER}|Function {_NAME}\(\)) should return {_TYPE} but returns {_TYPE}\.",
        rf"Parameter #[1-9][0-9]? \$[A-Za-z_][A-Za-z0-9_]* of (?:method {_MEMBER}|function {_NAME}(?:\(\))?) expects {_TYPE}, {_TYPE} given\.",
        rf"Property {_MEMBER} \({_TYPE}\) does not accept {_TYPE}\.",
        rf"Access to an undefined property {_MEMBER}\.",
        rf"Call to an undefined (?:static )?method {_MEMBER}\.",
        rf"Function {_NAME} not found\.",
        rf"Class {_NAME} extends unknown class {_NAME}\.",
        rf"Class {_NAME} implements unknown interface {_NAME}\.",
        rf"Class {_NAME} uses unknown trait {_NAME}\.",
        rf"Attribute class {_NAME} does not exist\.",
    )
)


def contains_credential_prefix(text: str) -> bool:
    """Recognize conservative credential prefixes in bounded native context."""
    return bool(_CREDENTIAL_PREFIX.search(text))


def diagnostic_message(message: str) -> str:
    """Admit useful native templates only when their entire context is safe."""
    if len(message) > 300 or not message.isascii():
        return ""
    if re.search(r"[\x00-\x1f\x7f]|[A-Za-z0-9_=-]{24,}", message):
        return ""
    if contains_credential_prefix(message):
        return ""
    if redact(message) != message:
        return ""
    return message if any(pattern.fullmatch(message) for pattern in _TEMPLATES) else ""
