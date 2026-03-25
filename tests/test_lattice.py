"""Tests for breaking_ecdsa_with_lll.lattice."""

from __future__ import annotations

from fractions import Fraction

import pytest

from breaking_ecdsa_with_lll.lattice import (
    DEFAULT_ORDER,
    _modular_inv,
    make_matrix,
    privkeys_from_reduced_matrix,
    reduce_matrix,
)

ORDER = DEFAULT_ORDER

# Minimal valid synthetic data (values are small integers, not real signatures,
# but sufficient to exercise all code paths without running actual LLL).
MSGS = [0xABCD, 0x1234, 0x5678]
SIGS = [(0xAAAA, 0xBBBB), (0xCCCC, 0xDDDD), (0xEEEE, 0xFFFF)]
PUBS = ["0000", "0000", "0000"]
B = 16


class TestModularInv:
    def test_modular_inv_basic(self) -> None:
        assert _modular_inv(3, 7) == 5  # 3*5 = 15 ≡ 1 (mod 7)

    def test_modular_inv_large(self) -> None:
        result = _modular_inv(0xBBBB, ORDER)
        assert (0xBBBB * result) % ORDER == 1

    def test_modular_inv_no_inverse_raises(self) -> None:
        with pytest.raises(ValueError):
            _modular_inv(0, 7)


class TestMakeMatrix:
    def test_make_matrix_returns_list_of_lists(self) -> None:
        m = make_matrix(MSGS, SIGS, PUBS, B, ORDER)
        assert isinstance(m, list)
        assert all(isinstance(row, list) for row in m)

    def test_make_matrix_shape(self) -> None:
        # Expect (m+1) rows × (m+1) cols where m = len(msgs)
        m_count = len(MSGS)
        mat = make_matrix(MSGS, SIGS, PUBS, B, ORDER)
        # rows = m-1 diagonal rows + 2 extra rows = m+1 total
        assert len(mat) == m_count + 1
        for row in mat:
            assert len(row) == m_count + 1

    def test_make_matrix_diagonal_entries_are_order(self) -> None:
        mat = make_matrix(MSGS, SIGS, PUBS, B, ORDER)
        for i in range(len(MSGS) - 1):
            assert mat[i][i] == ORDER

    def test_make_matrix_last_entry_is_power_of_two(self) -> None:
        mat = make_matrix(MSGS, SIGS, PUBS, B, ORDER)
        last_row = mat[-1]
        assert last_row[-1] == 2**B

    def test_make_matrix_too_few_sigs_raises(self) -> None:
        with pytest.raises(ValueError, match="At least 2"):
            make_matrix([0xABCD], [(0xAA, 0xBB)], ["0000"], B, ORDER)

    def test_make_matrix_exactly_two_sigs(self) -> None:
        # Must not raise
        mat = make_matrix(MSGS[:2], SIGS[:2], PUBS[:2], B, ORDER)
        assert len(mat) == 3  # 2+1


class TestReduceMatrix:
    def _small_identity(self) -> list[list[int | Fraction]]:
        """Return a 3×3 identity-ish matrix safe for LLL."""
        return [
            [100, 0, 0],
            [0, 100, 0],
            [0, 0, 100],
        ]

    def test_reduce_matrix_returns_list(self) -> None:
        mat = self._small_identity()
        result = reduce_matrix(mat)
        assert isinstance(result, list)

    def test_reduce_matrix_shape_preserved(self) -> None:
        mat = self._small_identity()
        result = reduce_matrix(mat)
        assert len(result) == len(mat)
        for row in result:
            assert len(row) == len(mat[0])

    def test_reduce_matrix_no_bkz(self) -> None:
        mat = self._small_identity()
        result = reduce_matrix(mat, do_bkz=False)
        assert result is not None


class TestPrivkeysFromReducedMatrix:
    def test_privkeys_returns_list(self) -> None:
        mat = make_matrix(MSGS, SIGS, PUBS, B, ORDER)
        reduced = reduce_matrix(mat)
        keys = privkeys_from_reduced_matrix(MSGS, SIGS, PUBS, reduced, ORDER)
        assert isinstance(keys, list)

    def test_privkeys_are_integers(self) -> None:
        mat = make_matrix(MSGS, SIGS, PUBS, B, ORDER)
        reduced = reduce_matrix(mat)
        keys = privkeys_from_reduced_matrix(MSGS, SIGS, PUBS, reduced, ORDER)
        assert all(isinstance(k, int) for k in keys)

    def test_privkeys_are_deduplicated(self) -> None:
        mat = make_matrix(MSGS, SIGS, PUBS, B, ORDER)
        reduced = reduce_matrix(mat)
        keys = privkeys_from_reduced_matrix(MSGS, SIGS, PUBS, reduced, ORDER)
        assert len(keys) == len(set(keys))

    def test_privkeys_less_than_order(self) -> None:
        mat = make_matrix(MSGS, SIGS, PUBS, B, ORDER)
        reduced = reduce_matrix(mat)
        keys = privkeys_from_reduced_matrix(MSGS, SIGS, PUBS, reduced, ORDER)
        assert all(0 <= k < ORDER for k in keys)
