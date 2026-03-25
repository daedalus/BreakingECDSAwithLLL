# BreakingECDSAwithLLL

> Recover ECDSA private keys from biased-nonce signatures via LLL/BKZ lattice reduction.

![lint_python](https://github.com/daedalus/BreakingECDSAwithLLL/workflows/lint_python/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/breaking-ecdsa-with-lll.svg)](https://pypi.org/project/breaking-ecdsa-with-lll/)
[![Python](https://img.shields.io/pypi/pyversions/breaking-ecdsa-with-lll.svg)](https://pypi.org/project/breaking-ecdsa-with-lll/)
[![Coverage](https://codecov.io/gh/daedalus/BreakingECDSAwithLLL/branch/main/graph/badge.svg)](https://codecov.io/gh/daedalus/BreakingECDSAwithLLL)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![GitHub issues](https://img.shields.io/github/issues/daedalus/BreakingECDSAwithLLL.svg)](https://github.com/daedalus/BreakingECDSAwithLLL/issues)
[![GitHub forks](https://img.shields.io/github/forks/daedalus/BreakingECDSAwithLLL.svg)](https://github.com/daedalus/BreakingECDSAwithLLL/network)
[![GitHub stars](https://img.shields.io/github/stars/daedalus/BreakingECDSAwithLLL.svg)](https://github.com/daedalus/BreakingECDSAwithLLL/stargazers)

The core idea: if you have many ECDSA signatures generated with a private key
whose nonces have a fixed-bit bias, those signatures converge toward the private
key via the **Hidden Number Problem (HNP)**. We solve HNP with the
Lenstra–Lenstra–Lovász (LLL) lattice reduction algorithm, optionally followed
by a BKZ post-processing pass.

The main countermeasure against this attack is using deterministic signatures
like `Z = H(h || d)` (RFC 6979), which eliminates nonce bias entirely.

Based on prior work:
- https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
- https://www.youtube.com/watch?v=6ssTlSSIJQE

Referenced in [CVE-2024-31497](https://nvd.nist.gov/vuln/detail/CVE-2024-31497) on 4/16/2024.

## Install

```bash
pip install breaking-ecdsa-with-lll
# With weak-signature generator support:
pip install "breaking-ecdsa-with-lll[generator]"
```

## Quick start

```bash
# (Victim) generate 6 weak signatures
gen-weak-sigs e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 176 6 > nonces.csv

# (Attacker) recover the private key
break-ecdsa nonces.csv 176 6 | grep e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

## Python API

```python
from breaking_ecdsa_with_lll import (
    load_csv,
    make_matrix,
    reduce_matrix,
    privkeys_from_reduced_matrix,
    display_keys,
)

msgs, sigs, pubs = load_csv("nonces.csv", limit=6)
matrix = make_matrix(msgs, sigs, pubs, B=176)
reduced = reduce_matrix(matrix, do_bkz=False)
keys = privkeys_from_reduced_matrix(msgs, sigs, pubs, reduced)
display_keys(keys)
```

## CLI reference

### `break-ecdsa`

```
ecdsa-break <filename> <B> <limit> [--matrix_type dense|sparse]
            [--order N] [--bkz] [--mmap]
```

### `gen-weak-sigs`

```
gen-weak-sigs <secret_hex> <bits> <n> [--mode MSB|LSB]
```

## API

| Symbol | Module | Description |
|---|---|---|
| `load_csv` | `io` | Load signatures from CSV |
| `make_matrix` | `lattice` | Build HNP lattice matrix |
| `reduce_matrix` | `lattice` | LLL (+ optional BKZ) reduction |
| `privkeys_from_reduced_matrix` | `lattice` | Extract private key candidates |
| `display_keys` | `display` | Print keys as 64-char hex strings |
| `generate_weak_signatures` | `generator` | Produce biased-nonce test signatures |
| `DEFAULT_ORDER` | `lattice` | secp256k1 group order |

## Development

```bash
git clone https://github.com/daedalus/BreakingECDSAwithLLL.git
cd BreakingECDSAwithLLL
pip install -e ".[test]"

# Run tests
pytest

# Format
ruff format src/ tests/

# Lint
ruff check src/ tests/

# Type check
mypy src/
```
