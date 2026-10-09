"""Frozen entry point for AEGIS.

PyInstaller needs a top-level script. `aegis/__main__.py` uses relative imports,
which have no package context when frozen, so this thin absolute-import shim exists
purely as the exe entry point.
"""
from __future__ import annotations

import multiprocessing
import sys


def main() -> int:
    # Required so a frozen build can spawn subprocesses (used by the lab/atomic
    # suites and by multiprocessing on Windows).
    multiprocessing.freeze_support()
    from aegis.cli import main as cli_main
    return cli_main()


if __name__ == "__main__":
    sys.exit(main())
