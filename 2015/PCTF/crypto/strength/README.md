# Plaid CTF 2015: Strength

**Category:** Crypto
**Points:** 110
**Description:** 

>Strength in Difference
>
>We've [captured](challenge/captured) the flag encrypted several times... do you think you can recover it?

## Write-up

The challenge consists of a file containing a collection of tuples:

>{N : e : c}
>{0xa5f7f8aaa82921f70aad9ece4eb77b62112f51ac2be75910b3137a28d22d7ef3be3d734dabb9d853221f1a17b1afb956a50236a7e858569cdfec3edf350e1f88ad13c1efdd1e98b151ce2a207e5d8b6ab31c2b66e6114b1d5384c5fa0aad92cc079965d4127339847477877d0a057335e2a761562d2d56f1bebb21374b729743L : 0x1614984a0df : 0x7ded5789929000e4d7799f910fdbe615824d04b055336de784e88ba2d119f0c708c3b21e9d551c15967eb00074b7f788d3068702b2209e4a3417c0ca09a0a2da4378aa0b16d20f2611c4658e090e7080c67dda287e7a91d8986f4f352625dceb135a84a4a7554e6b5bd95050876e0dca96dc21860df84e53962d7068cebd248dL}
>{0xa5f7f8aaa82921f70aad9ece4eb77b62112f51ac2be75910b3137a28d22d7ef3be3d734dabb9d853221f1a17b1afb956a50236a7e858569cdfec3edf350e1f88ad13c1efdd1e98b151ce2a207e5d8b6ab31c2b66e6114b1d5384c5fa0aad92cc079965d4127339847477877d0a057335e2a761562d2d56f1bebb21374b729743L : 0x15ef25e10f54a3 : 0x7c5b756b500801e3ad68bd4f2d4e1a3ff94d049774bc9c37a05d4c18d212c5b223545444e7015a7600ecff9a75488ed7e609c3e931d4b2683b5954a5dc3fc2de9ae3392de4d86d77ee4920fffb13ad59a1e08fd25262a700eb26b3f930cbdc80513df3b7af62ce22ab41d2546b3ac82e7344fedf8a25abfb2cbc717bea46c47eL}
>(...)

As with [curious](https://github.com/smokeleeteveryday/CTF_WRITEUPS/tree/master/2015/PCTF/crypto/curious), the first line gives us a hint about the encryption scheme as the parameters N, e and c are usually used to denote the modulus, public exponent and ciphertext in RSA.

The first thing we notice is that all moduli are identical, which can [prove to be exploitable](http://diamond.boisestate.edu/~liljanab/ISAS/course_materials/AttacksRSA.pdf). Consider the following:

Given our plaintext m and a set of n tuples {N, ei, ci} such that m^ei mod N = ci if we have two tuples {N, ei, ci}, {N, ej, cj} (i != j) such that gcd(ei, ej) = 1 then we can apply the Extended Euclidian Algorithm to obtain egcd(ei, ej) = ai*ei + aj*ej = 1. Consider ci^ai * cj^aj = (m^ei)^ai * (m^ej)^aj = m^(ei*ai) * m^(ej*aj) = m^(ei*ai + ej*aj) = m^1 = m (all mod N of course). A potential problem arises, however, when ai or aj is negative. Consider aj is negative then we will have to find the modular multiplicative inverse of the corresponding ciphertext cj and calculate b = (gcd(e1, e2)-(a*e1))/e2 so we can calculate ci^ai * modInv(cj, N)^(-b) % N = m. We iterate over the tuples and checking each combination for a suitable candidate with [this little script](solution/strength_crack.py):

>```python
>#!/usr/bin/python
>#
># Plaid CTF 2015
># Strength (CRYPTO/110)
>#
># @a: Smoke Leet Everyday
># @u: https://github.com/smokeleeteveryday
>#
>
># GCD (times sign of b if b is nonzero, times sign of a if b is zero)
>def gcd(a,b):
>  while b != 0:
>      a,b = b, a % b
>  return a
>
># Extended Greatest Common Divisor
>def egcd(a, b):
>  if (a == 0):
>      return (b, 0, 1)
>  else:
>      g, y, x = egcd(b % a, a)
>      return (g, x - (b // a) * y, y)
>
># Modular multiplicative inverse
>def modInv(a, m):
>  g, x, y = egcd(a, m)
>  if (g != 1):
>      raise Exception("[-]No modular multiplicative inverse of %d under modulus %d" % (a, m))
>  else:
>      return x % m
>
>def to_bytes(n, length, endianess='big'):
>   h = '%x' % n
>   s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
>   return s if endianess == 'big' else s[::-1]
>
>crypt_tups = []
>lines = open("captured", "rb").read().split("\n")
>lines = lines[1:len(lines)-1] # get rid of first and last line
>for line in lines:
>	tups = line[1:len(line)-1].split(":")
>	N, e, c = [long(x.strip(),16) for x in tups]
>	crypt_tups.append((N, e, c))
>
>for i in xrange(len(crypt_tups)):
>	for j in xrange(len(crypt_tups)):
>		if(i == j):
>			continue
>
>		N1, e1, c1 = crypt_tups[i]
>		N2, e2, c2 = crypt_tups[j]
>
>		assert (N1 == N2)
>
>		#a1*e1 + a2*e2 = 1
>		if (gcd(e1, e2) == 1):
>			#a = a1 % e2
>			a = modInv(e1, e2)
>			#b = (gcd(e1, e2)-(a*e1))/e2 (will be negative)
>			b = long((float(gcd(e1, e2)-(a*e1)))/float(e2))
>
>			assert (b < 0)
>
>			# Modular multiplicative inverse
>			c2i = modInv(c2, N1)
>			c1a = pow(c1, a, N1)
>			c2b = pow(c2i, long(-b), N1)
>			m = (c1a * c2b) % N1
>
>			print to_bytes(m, 16)
>			exit()
>```

Which gives us:

>```bash
>$ python strength_crack.py
>flag_Strength_Lies_In_Differences
>```