"""Synthetic weak-nonce ECDSA signature generator (for testing and demos)."""

from __future__ import annotations

import random

from ecdsa_break.lattice import DEFAULT_ORDER


def generate_weak_signatures(
    secret: int,
    bits: int,
    n: int,
    mode: str = "MSB",
    order: int = DEFAULT_ORDER,
) -> list[str]:
    """Generate *n* ECDSA signatures whose nonces have a known-bit bias.

    Uses the ``ecdsa`` package (optional dependency).

    Args:
        secret: The private key as a positive integer.
        bits: Number of known bias bits in the nonce.
        n: Number of signatures to generate.
        mode: ``"MSB"`` — the *bits* most-significant bits are fixed;
              ``"LSB"`` — the *bits* least-significant bits are fixed.
        order: Curve group order (default: secp256k1).

    Returns:
        A list of CSV lines in the format
        ``"1111,<R_hex>,<S_hex>,<Z_hex>,0000"``.

    Raises:
        ValueError: If *secret*, *n*, or *bits* is not positive.
    """
    if secret <= 0:
        raise ValueError(f"secret must be a positive integer; got {secret}")
    if n <= 0:
        raise ValueError(f"n must be a positive integer; got {n}")
    if bits <= 0:
        raise ValueError(f"bits must be a positive integer; got {bits}")

    try:
        import ecdsa as _ecdsa  # noqa: PLC0415
        import ecdsa.ecdsa as _ecdsa_core  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "The 'ecdsa' package is required for signature generation. "
            "Install it with: pip install ecdsa"
        ) from exc

    bias = 1 << bits
    gen = _ecdsa.SECP256k1.generator
    pub_key = _ecdsa_core.Public_key(gen, gen * secret)
    priv_key = _ecdsa_core.Private_key(pub_key, secret)

    fixed_bits = random.randrange(bias, order)

    if mode == "MSB":
        nonces = [fixed_bits + random.randrange(1, bias) for _ in range(n)]
    else:
        nonces = [random.randrange(bias, order) + fixed_bits for _ in range(n)]

    msgs = [random.randrange(1, order) for _ in range(n)]
    sigs_list = [priv_key.sign(msgs[i], nonces[i]) for i in range(n)]

    lines: list[str] = []
    for i in range(n):
        r_hex = format(sigs_list[i].r, "064x")
        s_hex = format(sigs_list[i].s, "064x")
        z_hex = format(msgs[i], "064x")
        lines.append(f"1111,{r_hex},{s_hex},{z_hex},0000")

    return lines
