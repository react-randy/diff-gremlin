"""Validate PHP helper evidence against the exact submitted source."""

import base64
import hashlib
import json
import re

from diff_gremlin.analyzers.php.token_model import PHPFileTokens, PHPToken
from diff_gremlin.domain.context import SourceFile


def _tokens(values: object, source: bytes) -> tuple[PHPToken, ...]:
    if not isinstance(values, list):
        raise ValueError("invalid token inventory")
    result = []
    pieces = []
    line = column = 1
    for item in values:
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
        text = raw.decode("utf-8", errors="surrogateescape")
        pieces.append(raw)
        result.append(PHPToken(item[0], text, line, column))
        if b"\n" in raw:
            line += raw.count(b"\n")
            column = len(raw.rsplit(b"\n", 1)[1]) + 1
        else:
            column += len(raw)
    if b"".join(pieces) != source:
        raise ValueError("token inventory differs from submitted source")
    return tuple(result)


def parse_token_output(
    text: str, source: bytes, file: SourceFile, nonce: str
) -> tuple[PHPFileTokens, str]:
    value = json.loads(text)
    if (
        not isinstance(value, dict)
        or type(value.get("schema")) is not int
        or value.get("schema") != 1
        or value.get("nonce") != nonce
        or value.get("sha256") != hashlib.sha256(source).hexdigest()
        or not isinstance(value.get("version"), str)
        or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.-]+)?", value["version"])
    ):
        raise ValueError("invalid token provenance")
    error = value.get("parse_error")
    if error is not None:
        if (
            not isinstance(error, dict)
            or type(error.get("line")) is not int
            or not 1 <= error["line"] <= source.count(b"\n") + 1
            or value.get("tokens") != []
        ):
            raise ValueError("invalid parse error")
        return PHPFileTokens(file, (), error["line"]), value["version"]
    return PHPFileTokens(file, _tokens(value.get("tokens"), source)), value["version"]
