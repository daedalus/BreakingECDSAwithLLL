"""CLI entry points for BreakingECDSAwithLLL."""

from __future__ import annotations

import argparse
import sys

from breaking_ecdsa_with_lll.display import display_keys
from breaking_ecdsa_with_lll.io import load_csv
from breaking_ecdsa_with_lll.lattice import (
    DEFAULT_ORDER,
    make_matrix,
    privkeys_from_reduced_matrix,
    reduce_matrix,
)


def main() -> int:
    """CLI: recover ECDSA private keys from a biased-nonce signature CSV."""
    parser = argparse.ArgumentParser(
        description="Recover ECDSA private keys using LLL/BKZ lattice reduction."
    )
    parser.add_argument(
        "filename",
        help="CSV file with columns tx,R,S,Z,pub (hex values).",
    )
    parser.add_argument(
        "B",
        type=int,
        help="Bit-width parameter for matrix construction (e.g. 176).",
    )
    parser.add_argument(
        "limit",
        type=int,
        help="Maximum number of signatures to read from the file.",
    )
    parser.add_argument(
        "--matrix_type",
        choices=["dense", "sparse"],
        default="dense",
        help="Matrix type (default: dense).",
    )
    parser.add_argument(
        "--order",
        type=int,
        default=DEFAULT_ORDER,
        help="Curve group order (default: secp256k1).",
    )
    parser.add_argument(
        "--bkz",
        action="store_true",
        default=False,
        help="Run a BKZ post-processing pass after LLL.",
    )
    parser.add_argument(
        "--mmap",
        action="store_true",
        help="Use memory-mapped file I/O.",
    )

    args = parser.parse_args()

    msgs, sigs, pubs = load_csv(args.filename, limit=args.limit, mmap_flag=args.mmap)
    matrix = make_matrix(msgs, sigs, pubs, args.B, args.order, args.matrix_type)
    reduced = reduce_matrix(matrix, do_bkz=args.bkz)
    keys = privkeys_from_reduced_matrix(msgs, sigs, pubs, reduced, args.order)
    display_keys(keys)
    return 0


def main_generator() -> int:
    """CLI: generate synthetic weak-nonce ECDSA signatures."""
    parser = argparse.ArgumentParser(
        description="Generate ECDSA signatures with biased nonces."
    )
    parser.add_argument(
        "secret",
        help="Private key as a 64-char hex string.",
    )
    parser.add_argument(
        "bits",
        type=int,
        help="Number of known bias bits in each nonce.",
    )
    parser.add_argument(
        "n",
        type=int,
        help="Number of signatures to generate.",
    )
    parser.add_argument(
        "--mode",
        choices=["MSB", "LSB"],
        default="MSB",
        help="Bias position: MSB or LSB (default: MSB).",
    )

    args = parser.parse_args()
    secret_int = int(args.secret, 16)

    from breaking_ecdsa_with_lll.generator import (
        generate_weak_signatures,  # noqa: PLC0415
    )

    lines = generate_weak_signatures(secret_int, args.bits, args.n, mode=args.mode)
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
