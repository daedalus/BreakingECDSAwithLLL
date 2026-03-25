"""I/O helpers for loading ECDSA signature CSV files."""

from __future__ import annotations

import mmap
import os


def load_csv(
    filename: str | os.PathLike[str],
    limit: int | None = None,
    mmap_flag: bool = False,
) -> tuple[list[int], list[tuple[int, int]], list[str]]:
    """Load ECDSA signature data from a CSV file.

    The expected CSV format is one row per signature::

        <tx_hex>,<R_hex>,<S_hex>,<Z_hex>,<pub>

    Args:
        filename: Path to the CSV file.
        limit: Maximum number of rows to read.  ``None`` reads all rows.
            A value of ``0`` returns empty lists immediately.
        mmap_flag: If ``True``, memory-map the file for potentially faster I/O.

    Returns:
        A 3-tuple ``(msgs, sigs, pubs)`` where:

        - ``msgs[i]`` is the message hash as an integer.
        - ``sigs[i]`` is ``(R, S)`` as a pair of integers.
        - ``pubs[i]`` is the raw public-key field string.

    Raises:
        FileNotFoundError: If *filename* does not exist.
        ValueError: If a row has the wrong number of columns or contains a
            non-hexadecimal value in the R, S, or Z fields.
    """
    msgs: list[int] = []
    sigs: list[tuple[int, int]] = []
    pubs: list[str] = []

    if limit == 0:
        return msgs, sigs, pubs

    path = os.fspath(filename)

    if mmap_flag:
        with open(path, "rb") as f:
            file_size = os.path.getsize(path)
            if file_size == 0:
                return msgs, sigs, pubs
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            raw_lines = mm.read().decode("utf-8").splitlines()
            mm.close()
        lines: list[str] = raw_lines
    else:
        with open(path) as fp:
            lines = fp.readlines()

    for n, line in enumerate(lines):
        if limit is not None and n >= limit:
            break
        stripped = line.rstrip("\n\r")
        if not stripped:
            continue
        parts = stripped.split(",")
        if len(parts) != 5:
            raise ValueError(
                f"Row {n}: expected 5 comma-separated fields, got {len(parts)}: {stripped!r}"
            )
        _tx, r_hex, s_hex, z_hex, pub = parts
        try:
            msgs.append(int(z_hex, 16))
            sigs.append((int(r_hex, 16), int(s_hex, 16)))
        except ValueError as exc:
            raise ValueError(
                f"Row {n}: non-hexadecimal value in R/S/Z fields: {exc}"
            ) from exc
        pubs.append(pub)

    return msgs, sigs, pubs
