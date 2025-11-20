#!/usr/bin/env python3
"""Convenience wrapper to break all ciphertext files without fiddling with PYTHONPATH."""

from __future__ import annotations

import sys
from pathlib import Path

# make sure the python/ package directory is importable
REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "python"))

from break_all_messages import main  # type: ignore  # noqa: E402


if __name__ == "__main__":
    main()
