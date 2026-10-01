#!/usr/bin/env python3
"""Compatibility entry point; install the package once with uv tool install."""

from diff_gremlin.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
