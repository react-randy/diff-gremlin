"""Validate PHP helper evidence against the exact submitted source."""

import base64
import hashlib
import json
import re

from diff_gremlin.analyzers.php.token_coordinates import line_starts, token_position
from diff_gremlin.analyzers.php.token_model import PHPFileTokens, PHPToken
from diff_gremlin.domain.context import SourceFile


def _token_row(item: object) -> tuple[str, bytes]:
    if (
        not isinstance(item, list)
        or len(item) != 2
        or not isinstance(item[0], str)
        or not re.fullmatch(r"CHAR|T_[A-Z_]+", item[0])
        or not isinstance(item[1], str)
    ):
        raise ValueError("invalid token")
    raw = base64.b64decode(item[1], validate=True)
    if not raw:
        raise ValueError("empty token")
    return item[0], raw


def _tokens(values: object, source: bytes) -> tuple[PHPToken, ...]:
    if not isinstance(values, list):
        raise TypeError("invalid token inventory")
    result = []
    starts = line_starts(source)
    offset = 0
    for item in values:
        kind, raw = _token_row(item)
        if source[offset : offset + len(raw)] != raw:
            raise ValueError("token inventory differs from submitted source")
        line, column = token_position(starts, offset)
        result.append(
            PHPToken(kind, raw.decode("utf-8", errors="surrogateescape"), line, column)
        )
        offset += len(raw)
    if offset != len(source):
        raise ValueError("token inventory differs from submitted source")
    return tuple(result)


def _provenance(value: object, source: bytes, nonce: str) -> dict:
    if (
        not isinstance(value, dict)
        or type(value.get("schema")) is not int
        or value.get("schema") != 1
        or value.get("nonce") != nonce
        or value.get("sha256") != hashlib.sha256(source).hexdigest()
    ):
        raise ValueError("invalid token provenance")
    return value


def _version(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", value
    ):
        raise ValueError("invalid runtime version")
    return value


def _parse_error(error: object, values: object, source: bytes) -> int:
    if (
        not isinstance(error, dict)
        or type(error.get("line")) is not int
        or not 1 <= error["line"] <= len(line_starts(source))
        or values != []
    ):
        raise ValueError("invalid parse error")
    return error["line"]


def parse_token_output(
    text: str, source: bytes, file: SourceFile, nonce: str
) -> tuple[PHPFileTokens, str]:
    value = _provenance(json.loads(text), source, nonce)
    version = _version(value.get("version"))
    error = value.get("parse_error")
    if error is not None:
        line = _parse_error(error, value.get("tokens"), source)
        return PHPFileTokens(file, (), line), version
    return PHPFileTokens(file, _tokens(value.get("tokens"), source)), version
