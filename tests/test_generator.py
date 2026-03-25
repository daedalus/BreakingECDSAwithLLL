"""Tests for breaking_ecdsa_with_lll.generator."""

from __future__ import annotations

import pytest

from breaking_ecdsa_with_lll.generator import generate_weak_signatures

# A small but valid secp256k1 private key
SECRET = 0xE3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
BITS = 176
N = 4


class TestGenerateWeakSignatures:
    def test_returns_list_of_strings(self) -> None:
        lines = generate_weak_signatures(SECRET, BITS, N)
        assert isinstance(lines, list)
        assert all(isinstance(line_, str) for line_ in lines)

    def test_returns_n_lines(self) -> None:
        lines = generate_weak_signatures(SECRET, BITS, N)
        assert len(lines) == N

    def test_csv_format_five_fields(self) -> None:
        lines = generate_weak_signatures(SECRET, BITS, N)
        for line in lines:
            parts = line.split(",")
            assert len(parts) == 5, f"Expected 5 fields, got: {line!r}"

    def test_r_s_z_are_64_hex_chars(self) -> None:
        lines = generate_weak_signatures(SECRET, BITS, N)
        for line in lines:
            _, r, s, z, _ = line.split(",")
            assert len(r) == 64
            assert len(s) == 64
            assert len(z) == 64
            # Ensure they are valid hex
            int(r, 16)
            int(s, 16)
            int(z, 16)

    def test_lsb_mode(self) -> None:
        lines = generate_weak_signatures(SECRET, BITS, N, mode="LSB")
        assert len(lines) == N

    def test_invalid_secret_raises(self) -> None:
        with pytest.raises(ValueError, match="secret"):
            generate_weak_signatures(0, BITS, N)

    def test_invalid_n_raises(self) -> None:
        with pytest.raises(ValueError, match="n must"):
            generate_weak_signatures(SECRET, BITS, 0)

    def test_invalid_bits_raises(self) -> None:
        with pytest.raises(ValueError, match="bits must"):
            generate_weak_signatures(SECRET, 0, N)
