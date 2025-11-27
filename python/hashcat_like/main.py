"""
Main entry point for Enigma Hashcat with enhanced features

This module provides a unified interface to all hashcat functionality
with modern features for 2025.
"""

from __future__ import annotations

import sys
from typing import Optional

from .enhanced_cli import EnhancedCLI


def main() -> None:
    """Main entry point for Enigma Hashcat."""
    try:
        cli = EnhancedCLI()
        cli.main()
    except KeyboardInterrupt:
        print("\n[interrupt] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[error] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()