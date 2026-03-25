# SPEC.md — BreakingECDSAwithLLL

## Purpose

A Python library and CLI tool that recovers ECDSA private keys from a set of
signatures whose nonces have a bias (i.e. a fixed number of most- or least-
significant bits are known). The attack reduces to the Hidden Number Problem
(HNP) and solves it via Lenstra–Lenstra–Lovász (LLL) lattice reduction,
optionally followed by a BKZ post-processing pass.  The tool also ships a weak-
signature generator useful for end-to-end testing and demonstrations.

## Scope

### In scope
- Loading ECDSA signatures from a CSV file (format: `tx,R,S,Z,pub`)
- Optional memory-mapped file I/O for large datasets
- Constructing the HNP lattice matrix from signatures
- Reducing the lattice with LLL (via `olll`) and optionally BKZ (via `fpylll`)
- Extracting candidate private keys from the reduced matrix
- Displaying recovered keys as zero-padded 64-hex-digit strings
- Generating synthetic weak-nonce signatures for a given private key (CLI)
- A clean public Python API callable from other packages

### Out of scope
- Key-pair generation / full ECDSA signing infrastructure
- Support for curves other than secp256k1 (default order hard-coded)
- Automatic parameter tuning (B, number of signatures)
- Multi-threading / GPU acceleration

## Public API / Interface

### `breaking_ecdsa_with_lll.io`

```python
def load_csv(
    filename: str | os.PathLike[str],
    limit: int | None = None,
    mmap_flag: bool = False,
) -> tuple[list[int], list[tuple[int, int]], list[str]]:
    """Load ECDSA signature data from a CSV file.

    Args:
        filename: Path to CSV file with columns tx,R,S,Z,pub (hex).
        limit: Maximum number of rows to read.  None means read all.
        mmap_flag: If True use mmap for potentially faster I/O.

    Returns:
        (msgs, sigs, pubs) where msgs[i] is the message hash (int),
        sigs[i] = (R, S) as ints, pubs[i] is the raw pub-key string.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If a row has the wrong number of columns or a
            non-hexadecimal value in the R/S/Z fields.
    """
```

### `breaking_ecdsa_with_lll.lattice`

```python
DEFAULT_ORDER: int  # secp256k1 group order

def make_matrix(
    msgs: list[int],
    sigs: list[tuple[int, int]],
    pubs: list[str],
    B: int,
    order: int = DEFAULT_ORDER,
    matrix_type: str = "dense",
) -> list[list[int | Fraction]]:
    """Build the HNP lattice matrix.

    Args:
        msgs: Message hashes (integers).
        sigs: List of (R, S) signature pairs.
        pubs: Public-key strings (unused in construction, kept for API symmetry).
        B: Bit-width parameter (e.g. 176 for 80-bit nonce bias on secp256k1).
        order: Curve group order.
        matrix_type: "dense" (only option currently; reserved for future sparse).

    Returns:
        2-D list suitable for passing to reduce_matrix().

    Raises:
        ValueError: If len(msgs) < 2.
    """

def reduce_matrix(
    matrix: list[list[int | Fraction]],
    do_bkz: bool = False,
    delta: float = 0.75,
) -> list[list[int | Fraction]]:
    """Perform LLL (and optionally BKZ) reduction on the matrix.

    Args:
        matrix: Square matrix as returned by make_matrix().
        do_bkz: If True, follow LLL with a BKZ pass (block_size=20, max_loops=8).
        delta: LLL delta parameter (default 0.75).

    Returns:
        Reduced matrix in the same shape.
    """

def privkeys_from_reduced_matrix(
    msgs: list[int],
    sigs: list[tuple[int, int]],
    pubs: list[str],
    matrix: list[list[int | Fraction]],
    order: int = DEFAULT_ORDER,
) -> list[int]:
    """Extract candidate private keys from a reduced lattice matrix.

    Args:
        msgs: Original message hashes.
        sigs: Original (R, S) pairs.
        pubs: Public-key strings (unused; kept for symmetry).
        matrix: Reduced matrix from reduce_matrix().
        order: Curve group order.

    Returns:
        Deduplicated list of candidate private keys (integers).
    """
```

### `breaking_ecdsa_with_lll.display`

```python
def display_keys(keys: list[int]) -> None:
    """Print keys as zero-padded 64-char hex strings to stdout."""
```

### `breaking_ecdsa_with_lll.generator`

```python
def generate_weak_signatures(
    secret: int,
    bits: int,
    n: int,
    mode: str = "MSB",
    order: int = DEFAULT_ORDER,
) -> list[str]:
    """Generate n ECDSA signatures with biased nonces.

    Args:
        secret: Private key as integer.
        bits: Number of known bits in the nonce.
        n: Number of signatures to generate.
        mode: "MSB" (known most-significant bits) or "LSB".
        order: Curve order.

    Returns:
        List of CSV lines: "1111,<R_hex>,<S_hex>,<Z_hex>,0000".

    Raises:
        ValueError: If secret <= 0 or n <= 0 or bits <= 0.
    """
```

## Data Formats

CSV input (one row per signature):
```
<tx_hex>,<R_hex>,<S_hex>,<Z_hex>,<pub>
```
All numeric fields are hexadecimal strings without `0x` prefix; each is
zero-padded to 64 characters by convention (but any valid hex is accepted).

## Edge Cases

1. `limit=0` — `load_csv` must return empty lists, not raise.
2. `limit > actual_rows` — must not raise; just return what exists.
3. Single signature (`len(msgs) == 1`) — `make_matrix` raises `ValueError`
   because at least 2 signatures are required.
4. Duplicate nonce difference in the reduced matrix — `privkeys_from_reduced_matrix`
   returns deduplicated keys.
5. Matrix row that causes a zero-division during key extraction — silently skip
   and continue (already handled via try/except in original).
6. `mmap_flag=True` on an empty file — must return empty lists without error.
7. CSV row with wrong column count — raises `ValueError` with a descriptive
   message indicating the offending row index.

## Performance & Constraints

- Python 3.11+
- External dependencies: `olll`, `fpylll`, `ecdsa` (generator only)
- No other constraints; matrix construction is O(m) where m = number of sigs
