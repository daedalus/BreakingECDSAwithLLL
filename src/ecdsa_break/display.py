"""Output helpers for displaying recovered ECDSA private keys."""

from __future__ import annotations

import sys


def display_keys(keys: list[int]) -> None:
    """Print recovered private keys to stdout as zero-padded 64-char hex strings.

    Args:
        keys: List of private key integers to display.
    """
    sys.stdout.write("\n".join(f"{key:064x}" for key in keys) + "\n")
    sys.stdout.flush()
    sys.stderr.flush()
