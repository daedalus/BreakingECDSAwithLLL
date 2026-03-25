"""Tests for ecdsa_break.__main__ CLI entry points."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from ecdsa_break.__main__ import main, main_generator


class TestMainCli:
    def test_main_runs_end_to_end(
        self, minimal_csv_file: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """main() should exit 0 and print at least one 64-char hex key."""
        with patch("sys.argv", ["break-ecdsa", minimal_csv_file, "16", "3"]):
            rc = main()
        assert rc == 0
        captured = capsys.readouterr()
        lines = [line_ for line_ in captured.out.strip().splitlines() if line_]
        assert len(lines) >= 1
        for line in lines:
            assert len(line) == 64
            int(line, 16)  # must be valid hex

    def test_main_with_mmap_flag(
        self, minimal_csv_file: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with patch("sys.argv", ["break-ecdsa", minimal_csv_file, "16", "3", "--mmap"]):
            rc = main()
        assert rc == 0

    def test_main_with_bkz_flag(
        self, minimal_csv_file: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """BKZ on tiny synthetic data may raise ReductionError (degenerate
        lattice) or succeed — both are acceptable."""
        from fpylll.util import ReductionError  # type: ignore[import-untyped]

        with patch("sys.argv", ["break-ecdsa", minimal_csv_file, "16", "3", "--bkz"]):
            try:
                rc = main()
                assert rc == 0
            except ReductionError:
                pass  # expected on degenerate synthetic data

    def test_main_missing_file_raises(self) -> None:
        with patch("sys.argv", ["break-ecdsa", "/nonexistent.csv", "16", "3"]):
            with pytest.raises(FileNotFoundError):
                main()


class TestMainGeneratorCli:
    SECRET = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_main_generator_runs(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("sys.argv", ["gen-weak-sigs", self.SECRET, "176", "3"]):
            rc = main_generator()
        assert rc == 0
        captured = capsys.readouterr()
        lines = [line_ for line_ in captured.out.strip().splitlines() if line_]
        assert len(lines) == 3
        for line in lines:
            assert len(line.split(",")) == 5

    def test_main_generator_lsb_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch(
            "sys.argv", ["gen-weak-sigs", self.SECRET, "176", "2", "--mode", "LSB"]
        ):
            rc = main_generator()
        assert rc == 0
