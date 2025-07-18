#!/usr/bin/env python
# Author Dario Clavijo 2020
# based on previous work:
# https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
# https://www.youtube.com/watch?v=6ssTlSSIJQE

import sys
import argparse
import mmap
from sage.all_cmdline import *
import gmpy2

# Default order from secp256k1 curve
DEFAULT_ORDER = 115792089237316195423570985008687907852837564279074904382605163141518161494337


def modular_inv(a, b):
    """Efficient modular inverse"""
    return int(gmpy2.invert(a, b))


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
    m1, m2 = m + 1, m + 2
    sys.stderr.write(f"Using: {m} sigs...\n")
    
    if matrix_type == "sparse":
        matrix = SparseMatrix(QQ, m2, m2)
    else:
        matrix = Matrix(QQ, m2, m2)

    msgn, rn, sn = msgs[-1], sigs[-1][0], sigs[-1][1]
    mi_sn_order = modular_inv(sn, order)
    rnsn_inv = rn * mi_sn_order
    mnsn_inv = msgn * mi_sn_order

    for i in range(m):
        # Fill diagonal with the order
        matrix[i, i] = order
        # Set values for the matrix (only first m columns)
        mi_sigi_order = modular_inv(sigs[i][1], order)
        matrix[m, i] = (sigs[i][0] * mi_sigi_order) - rnsn_inv
        matrix[m1, i] = (msgs[i] * mi_sigi_order) - mnsn_inv

    # Populate last two columns with specific values
    B2 = 1 << B
    matrix[m, m1] = B2 / order
    matrix[m1, m1] = B2

    return matrix


def privkeys_from_reduced_matrix(msgs, sigs, pubs, matrix, order, max_rows=20):
    """
    Extract private keys by:
      • Precomputing (a,b,cd,ab_list) for all msgs,
      • Sorting rows by ||row|| ascending,
      • Testing only the top `max_rows` rows.
    """
    from math import sqrt
    keys = set()
    m = len(msgs)    
    msgn, rn, sn = msgs[-1], sigs[-1][0], sigs[-1][1]

    # 1) Precompute per-i constants
    params = []
    for i in range(m):
        a = rn * sigs[i][1]
        b = sn * sigs[i][0]
        c = sn * msgs[i]
        d = msgn * sigs[i][1]
        cd = (c - d) % order
        if a == b: ab_list = None
        else: ab_list = [ (a - b) % order, (b - a) % order ]
        params.append((b, cd, ab_list))

    # 2) Compute row norms once
    row_norms = []
    for idx, row in enumerate(matrix):
        # only consider first m components for the norm
        norm2 = sum((float(row[j])**2 for j in range(m)))
        row_norms.append((norm2, idx))
    row_norms.sort()

    # 3) Only test top max_rows shortest rows
    for _, ridx in row_norms[:max_rows]:
        row = matrix[ridx]
        # extract all potential k-diffs at once
        kdiffs = [int(row[j]) for j in range(m)]
        # for each message i, attempt recovery
        for i, (b, cd, ab_list) in enumerate(params):
            base = (cd - b * kdiffs[i])
            if ab_list is None:
                # special case a==b -> key = base
                if 0 < base < order: keys.add(base)
                else: keys.add(base % order)
            else:
                for ab in ab_list:
                    # modular_inv only if ab != 0
                    if ab:
                        inv = modular_inv(ab, order)
                        key = (base * inv)
                        if 0 < key < order: keys.add(key)
                        else: keys.add(key % order)
    return list(keys)



def display_keys(keys):
    """Display private keys in hexadecimal format."""
    sys.stdout.write("\n".join([f"{key:064x}" for key in keys]) + "\n")
    sys.stdout.flush()
    sys.stderr.flush()


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
        "--reduction", choices=["LLL", "BKZ"], default="LLL",
        help="Reduction algorithm: LLL (default) or BKZ"
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

    # Perform LLL or BKZ reduction
    if args.reduction == "LLL":
        new_matrix = matrix.LLL(early_red=True, use_siegel=True)
    else:
        new_matrix = matrix.BKZ(early_red=True, use_siegel=True)

    # Extract and display private keys
    keys = privkeys_from_reduced_matrix(msgs, sigs, pubs, new_matrix, args.order)
    display_keys(keys)


if __name__ == "__main__":
    main()
