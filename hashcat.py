#!/usr/bin/env python3
"""Entry point to run the hashcat-like CLI without fiddling with PYTHONPATH."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "python"))

from hashcat_like.cli import main  # type: ignore  # noqa: E402


if __name__ == "__main__":
    main()
