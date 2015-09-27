#!/usr/bin/env python
#
# Trend Micro CTF 2015
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#

from Crypto.PublicKey import RSA
from pyprimes import *
from factorlookup import *

# Extended Greatest Common Divisor
def egcd(a, b):
	if (a == 0):
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

# Modular multiplicative inverse
def modInv(a, m):
	g, x, y = egcd(a, m)
	if (g != 1):
		raise Exception("[-]No modular multiplicative inverse of %d under modulus %d" % (a, m))
	else:
		return x % m

ciphertext = "kPmDFLk5b/torG53sThWwEeNm0AIpEQek0rVG3vCttc=".decode('base64')
pubKey = RSA.importKey(open("../challenge/PublicKey.pem", 'rb').read())

print "[*]RSA Public key (n = %d, e = %d)" % (pubKey.n, pubKey.e)

# Get binary representation
binrep = "{0:b}".format(pubKey.n)

# Iterate over every bit and flip it
for pos in xrange(len(binrep)):
	c = list(binrep)
	c[pos] = "1" if (c[pos] == "0") else "0"
	candidate_binrep = "".join(c)
	candidate = int(candidate_binrep, 2)

	facstatus = isFactored(candidate)

	if(facstatus[0] > 4):
		if((len(facstatus[1]) == 2) and not(False in [isprime(x) for x in facstatus[1]])):
			print "[+]Found candidate! [%d] [%s]" % (candidate, facstatus[1])
			print "[+]Corresponding private exponent (d = %d)" % d
		else:
			continue

		p = facstatus[1][0]
		q = facstatus[1][1]
		d = modInv(pubKey.e, (p-1)*(q-1))
		privKey = RSA.construct((candidate, pubKey.e, d, p, q, ))

		p = privKey.decrypt(ciphertext)

		# If flag prefix is in plaintext we have our private key
		if("TMCTF" in p):
			print "[+]Plaintext: [%s]" % p
			exit()