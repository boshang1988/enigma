#!/usr/bin/env python3
"""
Enigma Hashcat - Modern password recovery toolkit for 2025

Entry point to run the enhanced hashcat-like CLI with modern features.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "python"))

from hashcat_like.main import main  # type: ignore  # noqa: E402


if __name__ == "__main__":
    main()