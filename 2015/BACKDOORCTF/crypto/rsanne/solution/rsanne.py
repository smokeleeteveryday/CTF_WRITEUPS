#!/usr/bin/python
#
# Backdoor CTF 2015
# RSANNE (CRYPTO/350) Exploit
#
# @a: Smoke Leet Everyday
# @u: https://github.com/smokeleeteveryday
#
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode

# GCD (times sign of b if b is nonzero, times sign of a if b is zero)
def gcd(a,b):
	while b != 0:
		a,b = b, a % b
	return a

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

# Decrypt ciphertext using private key (PKCS1 OAEP format)
def do_decrypt(rsakey, ciphertext):
	rsakey = PKCS1_OAEP.new(rsakey) 
	plaintext = rsakey.decrypt(b64decode(ciphertext)) 
	return plaintext

# Calculate private exponent from n, e, p, q
def getPrivate(n, e, p, q):
	d = modInv(e, (p-1)*(q-1))
	return RSA.construct((n, e, d, p, q, ))

# Factors of n expressed as (2^2281 - 1)(2^2203 - 1)
p = (pow(2, 2281)-1)
q = (pow(2, 2203)-1)

ciphertext = open("flag.enc", 'rb').read()
pubKey = RSA.importKey(open("id_rsa.pub", 'rb').read())
privKey = getPrivate(pubKey.n, pubKey.e, p, q)
print do_decrypt(privKey, ciphertext)