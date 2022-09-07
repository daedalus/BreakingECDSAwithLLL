#!/usr/bin/env python
# Author Dario Clavijo 2020
# based on previous work:
# https://blog.trailofbits.com/2020/06/11/ecdsa-handle-with-care/
# https://www.youtube.com/watch?v=6ssTlSSIJQE

import sys
#import ecdsa
import random
from sage.all_cmdline import *   
import gmpy2

# order is from secp256k1 curve it can be used any other.
order = int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)


def modular_inv(a,b):
  return int(gmpy2.invert(a,b))


def load_csv(filename, limit = None):
  msgs = []
  sigs = []
  pubs = []
  fp = open(filename)
  n=0
  if limit == None:
    limit = -1
  for line in fp:
    if (limit == -1) or (n < limit)) :
      l = line.rstrip().split(",")
      #sys.stderr.write(str(l)+"\n")
      tx,R,S,Z,pub = l
      msgs.append(int(Z,16))
      sigs.append((int(R,16),int(S,16)))
      pubs.append(pub)
      n+=1
  return msgs,sigs,pubs


def make_matrix(msgs,sigs,pubs):
  m = len(msgs)
  sys.stderr.write("Using: %d sigs...\n" % m)
  matrix = Matrix(QQ,m+2, m+2)

  msgn, rn, sn = [msgs[-1], sigs[-1][0], sigs[-1][1]]
  rnsn_inv = rn * modular_inv(sn, order)
  mnsn_inv = msgn * modular_inv(sn, order)

  for i in range(0,m):
    #matrix.append([0] * i + [order] + [0] * (m-i+1))
    matrix[i,i] = order

  for i in range(0,m):
    x0=(sigs[i][0] * modular_inv(sigs[i][1], order)) - rnsn_inv
    x1=(msgs[i] * modular_inv(sigs[i][1], order)) - mnsn_inv
    #print(m,i,x0,x1)
    matrix[m+0,i] = x0
    matrix[m+1,i] = x1
 
  matrix[m+0,i+1] = (int(2**B) / order)
  matrix[m+0,i+2] = 0
  matrix[m+1,i+1] = 0
  matrix[m+1,i+2] = 2**B

  return matrix


def privkeys_from_reduced_matrix(m):
  keys=[]
  for row in m:
    potential_nonce_diff = row[0]
    #print (potential_nonce_diff)
    # Secret key = (rns1 - r1sn)-1 (snm1 - s1mn - s1sn(k1 - kn))
    potential_priv_key = (sn * msgs[0]) - (sigs[0][1] * msgn) - (sigs[0][1] * sn * potential_nonce_diff)
    try:
      potential_priv_key *= modular_inv((rn * sigs[0][1]) - (sigs[0][0] * sn), order)

      key = potential_priv_key % order
      if key not in keys:
        keys.append(key)

    except Exception as e:
      sys.stderr.write(str(e)+"\n")
      pass
  return keys


def display_keys(keys):
  for key in keys:
    sys.stdout.write("%064x\n" % key)
    #sys.stderr.write("%064x\n" % key)
  sys.stdout.flush()
  sys.stderr.flush()


def main():
  filename = sys.argv[1]
  B = int(sys.argv[2])
  limit = int(sys.argv[3])
  run_mode = "LLL"

  msgs,sigs,pubs = load_csv(filename, limit = limit)
  
  matrix = make_matrix(msgs,sigs,pubs)

  if run_mode == "LLL":
    new_matrix = matrix.LLL(early_red=True, use_siegel=True)
    keys = privkeys_from_reduced_matrix(new_matrix)
  else:
    new_matrix = matrix.BKZ(early_red=True, use_siegel=True)
    keys = privkeys_from_reduced_matrix(new_matrix)

  display_keys(keys)
  
if __name__ == "__main__":
  main()

