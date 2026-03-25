# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0.1] - 2026-03-25

### Added
- `src/` layout with installable package `breaking_ecdsa_with_lll`
- `breaking_ecdsa_with_lll.io` — `load_csv` with optional mmap, limit, and robust error handling
- `breaking_ecdsa_with_lll.lattice` — `make_matrix`, `reduce_matrix` (LLL + optional BKZ), `privkeys_from_reduced_matrix`
- `breaking_ecdsa_with_lll.display` — `display_keys`
- `breaking_ecdsa_with_lll.generator` — `generate_weak_signatures` (MSB / LSB modes)
- CLI entry points `break-ecdsa` and `gen-weak-sigs`
- Full pytest suite with >80% coverage
- Type hints throughout; `py.typed` marker
- `pyproject.toml` with hatchling, ruff, mypy, pytest-cov
- Pre-commit hooks (ruff-format, ruff, mypy, pre-commit-hooks)
- GitHub Actions CI (test matrix 3.11/3.12/3.13, lint, build) and PyPI publish workflow
- `SPEC.md` contract document
