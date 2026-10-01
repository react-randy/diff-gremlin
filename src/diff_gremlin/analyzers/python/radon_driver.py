"""Read static Python text through Radon's metric API without CLI config."""

import json
import sys
from pathlib import Path


def main(paths: list[str]) -> int:
    try:
        from radon import __version__
        from radon.metrics import mi_visit
    except ImportError:
        print("Radon package is not installed", file=sys.stderr)
        return 3
    rows = {}
    try:
        for path in paths:
            rows[path] = {
                "mi": mi_visit(Path(path).read_text(encoding="utf-8"), multi=True)
            }
    except (OSError, UnicodeError, SyntaxError, ValueError):
        print(
            "Radon maintainability analysis failed for an input file", file=sys.stderr
        )
        return 2
    print(json.dumps({"version": __version__, "files": rows}, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
