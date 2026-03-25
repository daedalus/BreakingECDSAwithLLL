"""Tests for ecdsa_break.display."""

from __future__ import annotations

import pytest

from ecdsa_break.display import display_keys


class TestDisplayKeys:
    def test_display_keys_single_key(self, capsys: pytest.CaptureFixture[str]) -> None:
        display_keys([0xDEADBEEF])
        captured = capsys.readouterr()
        assert (
            "00000000000000000000000000000000000000000000000000000000deadbeef"
            in captured.out
        )

    def test_display_keys_multiple_keys(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        display_keys([1, 2, 3])
        captured = capsys.readouterr()
        lines = captured.out.strip().splitlines()
        assert len(lines) == 3

    def test_display_keys_zero_padded_to_64_chars(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        display_keys([1])
        captured = capsys.readouterr()
        line = captured.out.strip()
        assert len(line) == 64
        assert line == "0" * 63 + "1"

    def test_display_keys_empty_list_outputs_newline(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        display_keys([])
        captured = capsys.readouterr()
        assert captured.out == "\n"

    def test_display_keys_large_key(self, capsys: pytest.CaptureFixture[str]) -> None:
        key = 2**256 - 1
        display_keys([key])
        captured = capsys.readouterr()
        assert "f" * 64 in captured.out
