"""Invoke the trusted parser helper with bounded input, output and time."""

import base64
import json
from pathlib import Path

from diff_gremlin.domain.context import ScanContext
from diff_gremlin.domain.process import RunResult

_MAX_OUTPUT = 64 * 1024 * 1024


def run_parser(
    ctx: ScanContext, php: str, source: bytes, nonce: str, remaining: float
) -> RunResult:
    helper = Path(__file__).parent / "assets" / "tokens.php"
    return ctx.run(
        [php, "-n", str(helper)],
        cwd=ctx.scratch,
        timeout=remaining,
        output_limit=max(_MAX_OUTPUT, len(source) * 32),
        input_text=json.dumps(
            {"source": base64.b64encode(source).decode(), "nonce": nonce}
        ),
        data_output=True,
    )
