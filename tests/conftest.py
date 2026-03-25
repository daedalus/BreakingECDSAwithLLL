"""Shared pytest fixtures for BreakingECDSAwithLLL tests."""

from __future__ import annotations

import csv
import os

import pytest

from ecdsa_break.lattice import DEFAULT_ORDER

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _int_to_hex64(n: int) -> str:
    return format(n, "064x")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_order() -> int:
    """secp256k1 group order."""
    return DEFAULT_ORDER


@pytest.fixture()
def minimal_csv_file(tmp_path: os.PathLike[str]) -> str:
    """Write a small but valid CSV of synthetic signatures and return its path."""
    # Deterministic synthetic values that pass CSV parsing
    rows = [
        ("1111", _int_to_hex64(0xAA), _int_to_hex64(0xBB), _int_to_hex64(0xCC), "0000"),
        ("1111", _int_to_hex64(0xDD), _int_to_hex64(0xEE), _int_to_hex64(0xFF), "0000"),
        ("1111", _int_to_hex64(0x11), _int_to_hex64(0x22), _int_to_hex64(0x33), "0000"),
    ]
    path = str(tmp_path / "sigs.csv")
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(rows)
    return path


@pytest.fixture()
def single_row_csv_file(tmp_path: os.PathLike[str]) -> str:
    """CSV with exactly one row (triggers make_matrix ValueError)."""
    path = str(tmp_path / "single.csv")
    with open(path, "w") as f:
        f.write(f"1111,{_int_to_hex64(1)},{_int_to_hex64(2)},{_int_to_hex64(3)},0000\n")
    return path


@pytest.fixture()
def empty_csv_file(tmp_path: os.PathLike[str]) -> str:
    """Empty CSV file."""
    path = str(tmp_path / "empty.csv")
    open(path, "w").close()
    return path


@pytest.fixture()
def bad_columns_csv_file(tmp_path: os.PathLike[str]) -> str:
    """CSV with wrong number of columns."""
    path = str(tmp_path / "bad.csv")
    with open(path, "w") as f:
        f.write("only,three,fields\n")
    return path


@pytest.fixture()
def non_hex_csv_file(tmp_path: os.PathLike[str]) -> str:
    """CSV with non-hex value in the Z field."""
    path = str(tmp_path / "nonhex.csv")
    with open(path, "w") as f:
        f.write("1111,aabb,ccdd,NOTHEX,0000\n")
    return path
