import ecdsa
import random

secret = int(sys.argv[1],16)
bits = int(sys.argv[2])
n = int(sys.argv[3])


gen = ecdsa.SECP256k1.generator
order = gen.order()
#secret = random.randrange(1,order)


pub_key = ecdsa.ecdsa.Public_key(gen, gen * secret)
priv_key = ecdsa.ecdsa.Private_key(pub_key, secret)

# generate 80 most significant bits, nonce must be less than order
yubikey_fixed_prefix = random.randrange(2**bits, order)
 
msgs = [random.randrange(1, order) for i in range(n)]
nonces = [random.randrange(1, 2**bits) + yubikey_fixed_prefix for i in range(n)]
sigs = [priv_key.sign(msgs[i],nonces[i]) for i in range(n)]

def inttohex(i):
	tmpstr = hex(i)
	hexstr = tmpstr.replace('0x','').replace('L','').zfill(64)
	return hexstr

for i in range(0,len(msgs)):
  print("%s,%s,%s,%s,%s" % ("1111",inttohex(sigs[i].r),inttohex(sigs[i].s),inttohex(msgs[i]),"0000"))
