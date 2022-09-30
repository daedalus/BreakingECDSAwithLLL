import ecdsa
import random
import sys

secret = int(sys.argv[1],16)
bits = int(sys.argv[2])
n = int(sys.argv[3])
mode = 'MSB'

gen = ecdsa.SECP256k1.generator
order = gen.order()
#secret = random.randrange(1,order)


pub_key = ecdsa.ecdsa.Public_key(gen, gen * secret)
priv_key = ecdsa.ecdsa.Private_key(pub_key, secret)

fixed_bits = random.randrange(2**bits, order)

if mode == 'MSB':
    # generate n most significant bits, nonce must be less than order
    nonces = [fixed_bits + random.randrange(1, 2 ** bits) for i in range(n)]
else:
    # generate n least significant bits, nonce must be less than order
    nonces = [random.randrange(2 ** bits, order) + fixed_bits for i in range(n)]

msgs = [random.randrange(1, order) for i in range(n)]
sigs = [priv_key.sign(msgs[i],nonces[i]) for i in range(n)]

def inttohex(i):
	tmpstr = hex(i)
	hexstr = tmpstr.replace('0x','').replace('L','').zfill(64)
	return hexstr

for i in range(0,len(msgs)):
  print("%s,%s,%s,%s,%s" % ("1111",inttohex(sigs[i].r),inttohex(sigs[i].s),inttohex(msgs[i]),"0000"))
