"""Tests for ecdsa_break.io."""

from __future__ import annotations

import pytest

from ecdsa_break.io import load_csv


class TestLoadCsv:
    # -----------------------------------------------------------------------
    # Happy path
    # -----------------------------------------------------------------------

    def test_load_csv_returns_correct_lengths(self, minimal_csv_file: str) -> None:
        msgs, sigs, pubs = load_csv(minimal_csv_file)
        assert len(msgs) == 3
        assert len(sigs) == 3
        assert len(pubs) == 3

    def test_load_csv_msgs_are_integers(self, minimal_csv_file: str) -> None:
        msgs, _, _ = load_csv(minimal_csv_file)
        assert all(isinstance(m, int) for m in msgs)

    def test_load_csv_sigs_are_int_pairs(self, minimal_csv_file: str) -> None:
        _, sigs, _ = load_csv(minimal_csv_file)
        for r, s in sigs:
            assert isinstance(r, int)
            assert isinstance(s, int)

    def test_load_csv_pubs_are_strings(self, minimal_csv_file: str) -> None:
        _, _, pubs = load_csv(minimal_csv_file)
        assert all(isinstance(p, str) for p in pubs)

    def test_load_csv_hex_values_decoded_correctly(self, minimal_csv_file: str) -> None:
        msgs, sigs, _ = load_csv(minimal_csv_file)
        assert msgs[0] == 0xCC
        assert sigs[0] == (0xAA, 0xBB)

    def test_load_csv_with_mmap(self, minimal_csv_file: str) -> None:
        msgs_m, sigs_m, pubs_m = load_csv(minimal_csv_file, mmap_flag=True)
        msgs_r, sigs_r, pubs_r = load_csv(minimal_csv_file, mmap_flag=False)
        assert msgs_m == msgs_r
        assert sigs_m == sigs_r
        assert pubs_m == pubs_r

    # -----------------------------------------------------------------------
    # Limit parameter
    # -----------------------------------------------------------------------

    def test_load_csv_limit_zero_returns_empty(self, minimal_csv_file: str) -> None:
        msgs, sigs, pubs = load_csv(minimal_csv_file, limit=0)
        assert msgs == []
        assert sigs == []
        assert pubs == []

    def test_load_csv_limit_one_returns_one_row(self, minimal_csv_file: str) -> None:
        msgs, sigs, pubs = load_csv(minimal_csv_file, limit=1)
        assert len(msgs) == 1

    def test_load_csv_limit_exceeds_rows(self, minimal_csv_file: str) -> None:
        msgs, _, _ = load_csv(minimal_csv_file, limit=9999)
        assert len(msgs) == 3  # only 3 rows exist

    # -----------------------------------------------------------------------
    # Edge cases
    # -----------------------------------------------------------------------

    def test_load_csv_empty_file_returns_empty(self, empty_csv_file: str) -> None:
        msgs, sigs, pubs = load_csv(empty_csv_file)
        assert msgs == []
        assert sigs == []
        assert pubs == []

    def test_load_csv_empty_file_mmap_returns_empty(self, empty_csv_file: str) -> None:
        msgs, sigs, pubs = load_csv(empty_csv_file, mmap_flag=True)
        assert msgs == []

    def test_load_csv_file_not_found_raises(self, tmp_path: str) -> None:
        with pytest.raises(FileNotFoundError):
            load_csv(str(tmp_path) + "/nonexistent.csv")

    def test_load_csv_bad_columns_raises_value_error(
        self, bad_columns_csv_file: str
    ) -> None:
        with pytest.raises(ValueError, match="expected 5"):
            load_csv(bad_columns_csv_file)

    def test_load_csv_non_hex_raises_value_error(self, non_hex_csv_file: str) -> None:
        with pytest.raises(ValueError, match="non-hexadecimal"):
            load_csv(non_hex_csv_file)
